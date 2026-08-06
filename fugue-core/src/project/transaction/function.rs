use super::ProjectTransaction;
use super::reference::DerivedReferenceBatch;
use crate::il::common::IlArtefact;
use crate::il::pcode::PCodeIr;
use crate::ir::{
    Address, AddressRangeSet, CodeBlockId, Function, FunctionId, FunctionProperties,
    IncompleteFunction, IncompleteFunctionError, NormalisedFunctionRecord, ProblemKind, Reference,
    ReferenceKind, ReferenceOrigin, StagedFunctionChangeRecord,
};
use crate::project::{ChangeRecord, FunctionChangeKind, ProjectError};

struct StagedFunctionReferenceRecord {
    id: FunctionId,
    coverage: AddressRangeSet,
    references: Vec<Reference>,
}

impl ProjectTransaction<'_> {
    pub fn add_function(
        &mut self,
        function: IncompleteFunction,
    ) -> Result<FunctionId, ProjectError> {
        let record = self.stage_incomplete_function(function)?;
        self.replace_derived_references(record.coverage, ReferenceKind::Flow, record.references)?;
        Ok(record.id)
    }

    pub(crate) fn add_functions(
        &mut self,
        functions: impl IntoIterator<Item = IncompleteFunction>,
    ) -> Result<(), ProjectError> {
        let revision = self.project.revision();
        self.stage_function_batch(
            functions
                .into_iter()
                .map(|function| function.with_input_revision(revision).normalise()),
        )
    }

    fn stage_function_batch(
        &mut self,
        functions: impl IntoIterator<Item = Result<NormalisedFunctionRecord, IncompleteFunctionError>>,
    ) -> Result<(), ProjectError> {
        let functions = functions.into_iter();
        let expected = functions.size_hint().0;
        self.function_staging.reserve_functions(expected);
        self.changes.reserve(expected);
        let mut references = Vec::with_capacity(expected);
        for function in functions {
            let function = function?;
            let record = self.stage_normalised_function(function)?;
            references.push(DerivedReferenceBatch::new(
                record.coverage,
                ReferenceKind::Flow,
                record.references,
            ));
        }
        self.replace_derived_reference_batches(references)?;
        Ok(())
    }

    fn stage_incomplete_function(
        &mut self,
        function: IncompleteFunction,
    ) -> Result<StagedFunctionReferenceRecord, ProjectError> {
        let function = function.with_input_revision(self.project.revision());
        self.stage_normalised_function(function.normalise()?)
    }

    fn stage_normalised_function(
        &mut self,
        function: NormalisedFunctionRecord,
    ) -> Result<StagedFunctionReferenceRecord, ProjectError> {
        let entry = function.entry();
        let record = self.project.functions.stage_materialisation(
            &self.project.blocks,
            &mut self.function_staging,
            function,
        )?;
        self.stage_function_references(entry, record)
    }

    fn stage_function_membership(
        &mut self,
        mut function: Function,
    ) -> Result<StagedFunctionReferenceRecord, ProjectError> {
        function.set_input_revision(self.project.revision());
        let entry = function.entry();
        let record = self.project.functions.stage_membership(
            &self.project.blocks,
            &mut self.function_staging,
            function,
        )?;
        self.stage_function_references(entry, record)
    }

    fn stage_function_references(
        &mut self,
        entry: Address,
        mut record: StagedFunctionChangeRecord,
    ) -> Result<StagedFunctionReferenceRecord, ProjectError> {
        let id = record.id();
        let replaces_existing = record.replaces_existing();
        let previous_coverage = record.take_previous_coverage();
        let coverage = record.take_coverage();
        let covered = if replaces_existing {
            previous_coverage.union(&coverage)
        } else {
            coverage
        };
        let reference_coverage = covered.clone();
        self.call_graph_staging.set_function_edges(
            entry,
            record.take_call_targets(),
            !replaces_existing,
        );
        if replaces_existing {
            self.remove_lifted_descendants(id, &PCodeIr::FORM)?;
        }

        let references = record.take_references();

        if replaces_existing {
            self.changes.push(ChangeRecord::FunctionChanged {
                entry,
                kind: FunctionChangeKind::Body,
                coverage: covered,
            });
        } else {
            self.changes.push(ChangeRecord::FunctionAdded {
                entry,
                coverage: covered,
            });
        }

        Ok(StagedFunctionReferenceRecord {
            id,
            coverage: reference_coverage,
            references,
        })
    }

    pub fn set_function_properties(
        &mut self,
        entry: Address,
        properties: FunctionProperties,
    ) -> Result<bool, ProjectError> {
        let Some(coverage) = self.project.functions.stage_properties(
            &self.project.blocks,
            &mut self.function_staging,
            entry,
            properties,
            self.project.revision(),
        )?
        else {
            return Ok(false);
        };

        self.changes.push(ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Properties,
            coverage,
        });

        Ok(true)
    }

    /// Splits a function at one of its member blocks.
    ///
    /// Blocks reachable exclusively from `new_entry` move to the new function. Blocks
    /// reachable from both entries remain shared. The split is rejected when its boundary
    /// cannot be represented by unconditional tail-call branches.
    pub fn split_function(
        &mut self,
        function: FunctionId,
        new_entry: CodeBlockId,
    ) -> Result<Option<FunctionId>, ProjectError> {
        let Some(function) = self
            .project
            .functions
            .staged_by_id(&self.function_staging, function)?
        else {
            return Ok(None);
        };
        let Some((retained, split)) = function.split_at_block(new_entry, &self.project.blocks)
        else {
            return Ok(None);
        };
        if self
            .project
            .functions
            .staged_by_address(&self.function_staging, split.entry())?
            .is_some()
        {
            return Ok(None);
        }

        let split = self.stage_function_membership(split)?;
        let retained = self.stage_function_membership(retained)?;
        self.replace_derived_reference_batches([
            DerivedReferenceBatch::new(split.coverage, ReferenceKind::Flow, split.references),
            DerivedReferenceBatch::new(retained.coverage, ReferenceKind::Flow, retained.references),
        ])?;

        Ok(Some(split.id))
    }

    /// Merges `source` into `target`, preserving the target's identity.
    ///
    /// Membership and internal edges are united, former boundary tail calls become
    /// internal branches, and body-derived state is invalidated.
    pub fn merge_functions(
        &mut self,
        target: FunctionId,
        source: FunctionId,
    ) -> Result<bool, ProjectError> {
        if target == source {
            return Ok(false);
        }

        let Some(target_function) = self
            .project
            .functions
            .staged_by_id(&self.function_staging, target)?
        else {
            return Ok(false);
        };
        let Some(source_function) = self
            .project
            .functions
            .staged_by_id(&self.function_staging, source)?
        else {
            return Ok(false);
        };
        let Some(merged) = target_function.merge_with(&source_function, &self.project.blocks)
        else {
            return Ok(false);
        };
        let record = self.stage_function_membership(merged)?;
        self.remove_function_by_id(source, ReferenceOrigin::Derived)?;
        self.replace_derived_references(record.coverage, ReferenceKind::Flow, record.references)?;

        Ok(true)
    }

    pub fn remove_function(
        &mut self,
        entry: Address,
        origin: ReferenceOrigin,
    ) -> Result<bool, ProjectError> {
        let Some(function) = self
            .project
            .functions
            .staged_by_address(&self.function_staging, entry)?
        else {
            return Ok(false);
        };
        let id = function.id();

        self.remove_function_by_id(id, origin)
    }

    pub fn remove_function_by_id(
        &mut self,
        id: FunctionId,
        origin: ReferenceOrigin,
    ) -> Result<bool, ProjectError> {
        let Some(function) = self.stage_function_removal(id)? else {
            return Ok(false);
        };

        if origin.is_asserted() {
            self.add_problem(function.entry(), ProblemKind::HinderedByAssertedFact)?;
        }

        Ok(true)
    }

    pub(crate) fn stage_function_removal(
        &mut self,
        id: FunctionId,
    ) -> Result<Option<Function>, ProjectError> {
        let Some(mut removed) = self.project.functions.stage_removal(
            &self.project.blocks,
            &mut self.function_staging,
            id,
        )?
        else {
            return Ok(None);
        };
        let covered = removed.take_coverage();
        let function = removed.into_function();
        let entry = function.entry();
        self.call_graph_staging.remove_function_edges(entry);

        self.replace_derived_references(covered.clone(), ReferenceKind::Flow, [])?;

        self.remove_switches_of_function(id)?;

        self.remove_lifted_descendants(id, &PCodeIr::FORM)?;
        self.il_staging
            .remove_function(&self.project.storage, id)
            .map_err(ProjectError::from)?;

        self.changes.push(ChangeRecord::FunctionRemoved {
            entry,
            coverage: covered,
        });

        Ok(Some(function))
    }
}
