use super::ProjectTransaction;
use super::reference::DerivedReferenceBatch;
use crate::il::common::IlArtefact;
use crate::il::pcode::PCodeIr;
use crate::ir::{
    Address, AddressRangeSet, CodeBlockId, Function, FunctionId, FunctionProperties,
    FunctionRecord, IncompleteFunction, IncompleteFunctionError, ProblemKind, Reference,
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
        functions: impl IntoIterator<Item = Result<FunctionRecord, IncompleteFunctionError>>,
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
        function: FunctionRecord,
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

    pub fn update_function_properties(
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

#[cfg(test)]
mod test {
    use std::io;

    use super::*;
    use crate::ir::{
        FlowKind, IncompleteCodeBlock, IncompleteCodeBlockId, Insn, InsnEntry, ReferenceTarget,
    };
    use crate::lifter::{ContextBitRange, ContextSet};
    use crate::project::Project;
    use crate::storage::DEFAULT_SPACE_ID;

    fn writable_address(
        project: &Project,
        minimum_size: u64,
    ) -> Result<Address, Box<dyn std::error::Error>> {
        project
            .segments()
            .iter_views(DEFAULT_SPACE_ID)?
            .find(|view| view.properties().is_writable() && view.size() >= minimum_size)
            .map(|view| view.start())
            .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
    }

    fn push_block(function: &mut IncompleteFunction, insn: Insn) -> IncompleteCodeBlockId {
        let address = insn.address();
        let size = insn.size();
        let insn = match function.insn_entry(address) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => panic!("test instruction address must be unique"),
        };
        function.push_block(
            IncompleteCodeBlock::try_new(address, size, vec![insn], ContextSet::default())
                .expect("test instruction size must fit a code block"),
        )
    }

    fn partitioned_function(
        entry: Address,
        left: Address,
        right: Address,
        split: Address,
        shared: Address,
        external: Address,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let mut function = IncompleteFunction::new(entry);
        let entry_block = push_block(
            &mut function,
            Insn::from_direct_branch(entry, 1, right, true)?,
        );
        let left_block = push_block(
            &mut function,
            Insn::from_direct_branch(left, 1, split, false)?,
        );
        let right_block = push_block(
            &mut function,
            Insn::from_direct_branch(right, 1, shared, false)?,
        );
        let split_block = push_block(&mut function, Insn::from_direct_call(split, 1, external)?);
        let shared_block = push_block(&mut function, Insn::from_return(shared, 1)?);

        function.add_block_edge(entry_block, left_block)?;
        function.add_block_edge(entry_block, right_block)?;
        function.add_block_edge(left_block, split_block)?;
        function.add_block_edge(right_block, shared_block)?;
        function.add_block_edge(split_block, shared_block)?;
        function.mark_non_returning();
        Ok(function)
    }

    #[test]
    fn split_and_merge_follow_membership_and_control_flow() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)? + 0x100u64;
        let left = entry + 1u64;
        let right = entry + 0x10u64;
        let split = entry + 0x20u64;
        let shared = split + 1u64;
        let external = entry + 0x1000u64;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(partitioned_function(
                entry, left, right, split, shared, external,
            )?)?;
            transaction.commit()?;
            function
        };
        let (right_block, split_block) = project
            .functions()
            .get_by_id(function)
            .map(|function| {
                (
                    function.blocks_at(right).next(),
                    function.blocks_at(split).next(),
                )
            })
            .and_then(|(right, split)| right.zip(split))
            .expect("partition boundary blocks must exist");

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.split_function(function, right_block)?.is_none());
        }

        let child = {
            let mut transaction = project.transaction("test");
            let child = transaction
                .split_function(function, split_block)?
                .expect("function should split at its selected block");
            transaction.commit()?;
            child
        };

        let parent = project
            .functions()
            .get_by_id(function)
            .expect("parent function must survive");
        assert_eq!(
            parent
                .blocks()
                .map(|(address, _)| address)
                .collect::<Vec<_>>(),
            vec![entry, left, right, shared],
        );
        assert!(!parent.is_non_returning());
        assert_eq!(
            parent
                .flow_targets(project.blocks())
                .filter(|target| target.from() == left && target.to() == split)
                .map(|target| target.kind())
                .collect::<Vec<_>>(),
            vec![FlowKind::TailCallBranch],
        );
        drop(parent);

        let child_function = project
            .functions()
            .get_by_id(child)
            .expect("child function must exist");
        assert_eq!(
            child_function
                .blocks()
                .map(|(address, _)| address)
                .collect::<Vec<_>>(),
            vec![split, shared],
        );
        assert!(!child_function.is_non_returning());
        let shared_block = child_function
            .blocks_at(shared)
            .next()
            .expect("shared descendant must belong to the child");
        drop(child_function);
        assert_eq!(
            project
                .functions()
                .get_by_block_id(shared_block)
                .iter()
                .collect::<Vec<_>>(),
            vec![function, child],
        );
        assert!(
            project
                .references()
                .get(split, ReferenceTarget::from(external))?
                .is_some()
        );

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.merge_functions(function, child)?);
            transaction.commit()?;
        }

        let merged = project
            .functions()
            .get_by_id(function)
            .expect("merge target must survive");
        assert_eq!(
            merged
                .blocks()
                .map(|(address, _)| address)
                .collect::<Vec<_>>(),
            vec![entry, left, right, split, shared],
        );
        assert_eq!(
            merged
                .flow_targets(project.blocks())
                .filter(|target| target.from() == left && target.to() == split)
                .map(|target| target.kind())
                .collect::<Vec<_>>(),
            vec![FlowKind::Branch],
        );
        assert!(project.functions().get_by_id(child).is_none());
        assert!(
            project
                .references()
                .get(split, ReferenceTarget::from(external))?
                .is_some()
        );

        Ok(())
    }

    #[test]
    fn split_uses_block_identity_at_an_ambiguous_address() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)? + 0x200u64;
        let shared = entry + 0x10u64;
        let mut function = IncompleteFunction::new(entry);
        let entry_block = push_block(
            &mut function,
            Insn::from_direct_branch(entry, 1, shared, false)?,
        );
        let shared_insn = match function.insn_entry(shared) {
            InsnEntry::Vacant(entry) => entry.insert(Insn::from_return(shared, 1)?),
            InsnEntry::Occupied(_) => panic!("test instruction address must be unique"),
        };
        let context_bits = ContextBitRange::new(0, 0);
        let first_context = ContextSet::single(context_bits, 0);
        let second_context = ContextSet::single(context_bits, 1);
        let first = function.push_block(
            IncompleteCodeBlock::try_new(shared, 1, vec![shared_insn], first_context.clone())
                .ok_or("test block length must fit")?,
        );
        function.push_block(
            IncompleteCodeBlock::try_new(shared, 1, vec![shared_insn], second_context.clone())
                .ok_or("test block length must fit")?,
        );
        function.add_block_edge(entry_block, first)?;

        let function = {
            let mut transaction = project.transaction("test");
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };
        let new_entry = project
            .functions()
            .get_by_id(function)
            .expect("function must exist")
            .blocks_at(shared)
            .find(|block| {
                project
                    .blocks()
                    .get_by_id(*block)
                    .is_some_and(|block| block.context() == &second_context)
            })
            .expect("context-distinct split entry must exist");

        let child = {
            let mut transaction = project.transaction("test");
            let child = transaction
                .split_function(function, new_entry)?
                .expect("context-distinct block should become a function entry");
            transaction.commit()?;
            child
        };

        let parent = project
            .functions()
            .get_by_id(function)
            .expect("parent function must survive");
        let parent_block = parent
            .blocks_at(shared)
            .next()
            .expect("parent must retain the branch target");
        assert_eq!(parent.blocks_at(shared).count(), 1);
        assert_eq!(
            project
                .blocks()
                .get_by_id(parent_block)
                .expect("parent block must survive")
                .context(),
            &first_context,
        );
        assert_eq!(
            parent
                .flow_targets(project.blocks())
                .filter(|target| target.from() == entry && target.to() == shared)
                .map(|target| target.kind())
                .collect::<Vec<_>>(),
            vec![FlowKind::Branch],
        );
        assert_eq!(
            project
                .functions()
                .get_by_id(child)
                .expect("split function must exist")
                .entry_block(),
            Some(new_entry),
        );

        Ok(())
    }
}
