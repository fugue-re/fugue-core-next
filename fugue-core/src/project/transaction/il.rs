use std::any::Any;

use smallvec::SmallVec;

use super::ProjectTransaction;
use crate::il::common::{IlError, IlFormId, PersistableIl};
use crate::il::registry::IlFormRegistration;
use crate::ir::{AddressRange, FunctionId};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub(crate) fn materialise_erased(
        &mut self,
        form: &IlFormId,
        value: Box<dyn Any + Send + Sync>,
    ) -> Result<(), ProjectError> {
        if self.changes.semantic() {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        let admit = self
            .registry
            .form(form)
            .and_then(IlFormRegistration::admit)
            .ok_or_else(|| IlError::dialect_unavailable(form.as_str()))?;

        Ok(admit(
            &mut self.il_staging,
            &self.project.storage,
            value,
            self.project.semantic_revision(),
        )?)
    }

    pub fn replace_lifted<T>(&mut self, mut ir: T) -> Result<(), ProjectError>
    where
        T: PersistableIl,
    {
        if self.changes.semantic() {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        ir.metadata_mut()
            .set_input_revision(self.project.semantic_revision());

        self.il_staging.replace(&self.project.storage, ir)?;

        Ok(())
    }

    pub fn remove_lifted<T: PersistableIl>(
        &mut self,
        function: FunctionId,
    ) -> Result<bool, ProjectError> {
        Ok(self
            .il_staging
            .remove::<T>(&self.project.storage, function)?
            .is_some())
    }

    pub(crate) fn remove_lifted_by_form(
        &mut self,
        function: FunctionId,
        form: &IlFormId,
    ) -> Result<bool, ProjectError> {
        Ok(self
            .il_staging
            .remove_form(&self.project.storage, function, form)?)
    }

    pub fn remove_lifted_descendants(
        &mut self,
        function: FunctionId,
        first_invalid: &IlFormId,
    ) -> Result<usize, ProjectError> {
        let mut removed = 0usize;

        let registry = self.registry.clone();
        for form in registry.descendants(first_invalid) {
            if self.remove_lifted_by_form(function, form)? {
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn remove_lifted_descendants_in_range(
        &mut self,
        range: &AddressRange,
        first_invalid: &IlFormId,
    ) -> Result<usize, ProjectError> {
        let functions = self
            .project
            .functions
            .overlaps(&self.project.blocks, range)
            .collect::<SmallVec<[_; 8]>>();
        let mut removed = 0usize;

        for function in functions {
            removed += self.remove_lifted_descendants(function, first_invalid)?;
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod test {
    use crate::il::common::{
        IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlDominance, IlGraph, IlIndexRange,
        IlMetadata, IlSourceSpan, IlValueId,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeLiveness, ECodeUses};
    use crate::il::mcode::{MCodeBuilder, MCodeIr};
    use crate::il::pcode::{PCodeBuilder, PCodeIr};
    use crate::ir::{Address, FunctionId};
    use crate::project::{ChangeRecord, Project};
    use crate::storage::DEFAULT_SPACE_ID;

    fn tagged_source_spans(payload: &[u8]) -> Vec<IlSourceSpan> {
        let tag = payload.first().copied().unwrap_or_default();
        vec![IlSourceSpan::new(
            IlIndexRange::EMPTY,
            Address::new(DEFAULT_SPACE_ID, u64::from(tag)),
            u32::from(tag),
            u32::try_from(payload.len()).expect("test payload size should fit"),
        )]
    }

    fn single_block_graph() -> IlGraph {
        IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::EMPTY,
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
            Vec::new(),
        )
    }

    fn pcode_for_test(function: FunctionId, graph: IlGraph) -> PCodeIr {
        PCodeBuilder::new(IlMetadata::new(function, 0), graph)
            .build()
            .expect("test PCode IR should verify")
    }

    fn tagged_pcode(function: FunctionId, payload: &[u8]) -> PCodeIr {
        let mut builder = PCodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default());
        builder.set_source_spans(tagged_source_spans(payload));
        builder.build().expect("test PCode IR should verify")
    }

    fn ecode_for_test(function: FunctionId, graph: IlGraph) -> ECodeIr {
        ECodeBuilder::new(IlMetadata::new(function, 0), graph)
            .build()
            .expect("test ECode IR should verify")
    }

    fn mcode_for_test(function: FunctionId, graph: IlGraph) -> MCodeIr {
        MCodeBuilder::new(IlMetadata::new(function, 0), graph)
            .build()
            .expect("test MCode should verify")
    }

    #[test]
    fn rejecting_lifted_removal_preserves_materialised_ir() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let materialised = tagged_pcode(function, &[1, 2, 3]);

        let changes = {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(materialised.clone())?;
            transaction.commit()?
        };

        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    form: PCodeIr::FORM,
                })
        );
        assert_eq!(project.pcode(function)?.as_ref(), Some(&materialised));

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(tagged_pcode(function, &[4, 5, 6]))?;
            drop(transaction);
        }

        assert_eq!(project.pcode(function)?.as_ref(), Some(&materialised));

        let changes = {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted::<PCodeIr>(function)?);
            transaction.commit()?
        };

        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: PCodeIr::FORM,
        }));
        assert!(project.pcode(function)?.is_none());

        Ok(())
    }

    #[test]
    fn lifted_materialise_and_read() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let body = pcode_for_test(FunctionId::default(), IlGraph::default());

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(body.clone())?;
            transaction.commit()?;
        }

        let read = project
            .pcode(FunctionId::default())?
            .expect("PCode IR should be materialised");

        assert_eq!(read.ops(), body.ops());
        assert_eq!(
            read.metadata().input_revision(),
            project.semantic_revision()
        );

        Ok(())
    }

    #[test]
    fn project_reads_ecode_derived_tables() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(pcode_for_test(function, single_block_graph()))?;
            transaction.replace_lifted(ecode_for_test(function, single_block_graph()))?;
            transaction.commit()?;
        }

        let entry = IlBlockId::try_from_index(0)?;
        let value = IlValueId::try_from_index(0)?;
        let ir = project
            .ecode(function)?
            .expect("ECode IR should be available");
        let uses = ir.analyse::<ECodeUses>();
        let dominance = ir.analyse::<IlDominance>();
        let frontiers = dominance.frontiers(ir.graph().blocks(), ir.graph().successors());
        let liveness = ir.analyse::<ECodeLiveness>();

        assert!(uses.uses_for(value).is_empty());
        assert!(dominance.dominates(entry, entry));
        assert!(frontiers.frontier_for(entry).is_empty());
        assert!(liveness.live_in(entry).is_empty());
        assert!(liveness.live_out(entry).is_empty());

        Ok(())
    }

    #[test]
    fn lifted_descendant_removal_preserves_parent() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(tagged_pcode(function, &[1]))?;
            transaction.replace_lifted(ecode_for_test(function, IlGraph::default()))?;
            transaction.replace_lifted(mcode_for_test(function, IlGraph::default()))?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            assert_eq!(
                transaction.remove_lifted_descendants(function, &ECodeIr::FORM)?,
                2
            );
            drop(transaction);
        }

        assert!(project.ecode(function)?.is_some());
        assert!(project.mcode(function)?.is_some());

        let changes = {
            let mut transaction = project.transaction("test");
            assert_eq!(
                transaction.remove_lifted_descendants(function, &ECodeIr::FORM)?,
                2
            );
            transaction.commit()?
        };

        assert!(project.pcode(function)?.is_some());
        assert!(project.ecode(function)?.is_none());
        assert!(project.mcode(function)?.is_none());
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: ECodeIr::FORM,
        }));
        assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
            function,
            form: MCodeIr::FORM,
        }));

        Ok(())
    }
}
