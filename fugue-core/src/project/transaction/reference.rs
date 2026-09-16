use std::iter;

use super::ProjectTransaction;
use crate::ir::{
    AddressRangeSet, DerivedReferenceBatch, Reference, ReferenceKey, ReferenceKind,
    ReferenceOrigin, ReferenceProvenance,
};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub(crate) fn replace_derived_references(
        &mut self,
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        provenance: ReferenceProvenance,
        references: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        self.replace_derived_reference_batches(iter::once(DerivedReferenceBatch::new(
            coverage, kind, provenance, references,
        )))
    }

    pub(crate) fn replace_derived_reference_batches(
        &mut self,
        batches: impl IntoIterator<Item = DerivedReferenceBatch>,
    ) -> Result<bool, ProjectError> {
        self.reference_staging
            .replace_derived_reference_batches(&self.project.references, batches)
            .map_err(ProjectError::from)
    }

    pub fn add_reference(&mut self, reference: Reference) -> Result<bool, ProjectError> {
        self.reference_staging
            .insert(
                &self.project.references,
                reference.with_origin(ReferenceOrigin::Asserted),
            )
            .map_err(ProjectError::from)
    }

    pub fn remove_reference(&mut self, key: ReferenceKey) -> Result<bool, ProjectError> {
        self.reference_staging
            .remove(&self.project.references, key)
            .map_err(ProjectError::from)
    }
}

#[cfg(test)]
mod test {
    use std::io;

    use fugue_lifter::runtime::pcode::Inputs;

    use super::*;
    use crate::arch::Arch;
    use crate::engine::AnalysisEngine;
    use crate::il::common::{IlArtefact, IlError, IlGraph, IlIndexRange, IlMetadata, IlSourceSpan};
    use crate::il::ecode::{ECodeIr, ECodeOpcode, PCodeToECode};
    use crate::il::pcode::{
        PCodeBuilder, PCodeIr, PCodeLifterSpaceHandle, PCodeLocation, PCodeLocationProperties,
        PCodeOpSpec, PCodeOpcode,
    };
    use crate::ir::{
        Address, AddressRange, AddressWithContext, FunctionId, IncompleteCodeBlock,
        IncompleteFunction, Insn, InsnEntry, InsnProperties, ReferenceProperties, ReferenceTarget,
        Switch, SwitchCase, SwitchModel,
    };
    use crate::lifter::{ContextSet, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::project::{ChangeRecord, Project, ProjectTransaction};
    use crate::storage::{AddressSpaceId, DEFAULT_SPACE_ID};

    fn reference_key(from: Address, target: Address, kind: ReferenceKind) -> ReferenceKey {
        ReferenceKey::new(from, target.into(), kind)
    }

    fn pcode_reference_ir(
        function: FunctionId,
        source: Address,
        target_space: AddressSpaceId,
        target_offset: u64,
        opcode: PCodeOpcode,
    ) -> Result<PCodeIr, Box<dyn std::error::Error>> {
        let metadata = IlMetadata::new(function, 0);
        let mut builder = PCodeBuilder::new(metadata, IlGraph::default());

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1)?,
            source,
            0,
            1,
        )]);

        let pointer = builder.emitter().intern_location(PCodeLocation::new(
            PCodeLifterSpaceHandle::new(0),
            target_offset,
            8,
            PCodeLocationProperties::CONSTANT,
        ))?;
        let value = builder.emitter().intern_location(PCodeLocation::new(
            PCodeLifterSpaceHandle::new(1),
            0,
            8,
            PCodeLocationProperties::REGISTER,
        ))?;
        let output = opcode.requires_output().then_some(value);
        match opcode {
            PCodeOpcode::Store => {
                builder.emitter().emit(
                    PCodeOpSpec::new(opcode).with_address_space(target_space),
                    output,
                    [pointer, value],
                )?;
            }
            _ => {
                builder.emitter().emit(
                    PCodeOpSpec::new(opcode).with_address_space(target_space),
                    output,
                    [pointer],
                )?;
            }
        }

        Ok(builder.build()?)
    }

    fn pcode_copy_ir(
        function: FunctionId,
        source: Address,
    ) -> Result<PCodeIr, Box<dyn std::error::Error>> {
        let metadata = IlMetadata::new(function, 0);
        let mut builder = PCodeBuilder::new(metadata, IlGraph::default());

        builder.set_source_spans(vec![IlSourceSpan::new(
            IlIndexRange::new(0, 1)?,
            source,
            0,
            1,
        )]);

        let location = builder.emitter().intern_location(PCodeLocation::new(
            PCodeLifterSpaceHandle::new(1),
            0,
            8,
            PCodeLocationProperties::REGISTER,
        ))?;
        builder.emitter().emit(
            PCodeOpSpec::new(PCodeOpcode::Copy),
            Some(location),
            [location],
        )?;

        Ok(builder.build()?)
    }

    fn lift_test_ecode(source: &PCodeIr) -> Result<ECodeIr, IlError> {
        let arch = Arch::new(resolve_language("x86:LE:64").expect("test language should resolve"));
        let platform = arch.platform();
        PCodeToECode::default().transform(source, &arch, &platform)
    }

    fn stage_pcode_with_references(
        transaction: &mut ProjectTransaction<'_>,
        pcode: PCodeIr,
    ) -> Result<(), ProjectError> {
        let mut coverage = AddressRangeSet::new();
        pcode.reference_coverage_into(&mut coverage);
        let references = pcode.data_references().collect::<Vec<_>>();
        let provenance = ReferenceProvenance::Function(pcode.metadata().function());
        transaction.replace_lifted(pcode)?;
        transaction.replace_derived_references(
            coverage,
            ReferenceKind::Data,
            provenance,
            references,
        )?;
        Ok(())
    }

    #[test]
    fn project_remove_lifted_preserves_derived_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let load = pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, load.clone())?;
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(reference_key(source, target, ReferenceKind::Data))?
                .is_some()
        );

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted::<PCodeIr>(function)?);
            transaction.commit()?;
        }

        let retained = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("removing cached IL should preserve independently produced facts");
        assert!(retained.is_read());

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, load.clone())?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted::<PCodeIr>(function)?);
            drop(transaction);
        }

        let restored = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("rejection should preserve the artefact's derived data reference");
        assert!(restored.is_read());
        assert!(project.pcode(function)?.is_some());

        Ok(())
    }

    #[test]
    fn project_materialised_references_are_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let load = pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, load.clone())?;
            transaction.commit()?;
        }

        let changes = {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, load.clone())?;
            transaction.commit()?
        };
        assert!(
            !changes
                .records()
                .iter()
                .any(|record| matches!(record, ChangeRecord::ReferencesChanged { .. }))
        );

        Ok(())
    }

    #[test]
    fn derived_replacement_normalises_and_retracts_default_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(source));

        {
            let mut transaction = project.transaction("test");
            transaction.replace_derived_references(
                coverage.clone(),
                ReferenceKind::Data,
                ReferenceProvenance::Function(FunctionId::default()),
                [Reference::data(source, target, ReferenceProperties::READ)],
            )?;
            transaction.commit()?;
        }

        let stored = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("derived replacement should insert the reference");
        assert!(stored.origin().is_derived());

        {
            let mut transaction = project.transaction("test");
            transaction.replace_derived_references(
                coverage,
                ReferenceKind::Data,
                ReferenceProvenance::Function(FunctionId::default()),
                [],
            )?;
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(reference_key(source, target, ReferenceKind::Data))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn derived_replacement_preserves_an_asserted_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(source));

        {
            let mut transaction = project.transaction("test");
            transaction.add_reference(Reference::data(
                source,
                target,
                ReferenceProperties::WRITE,
            ))?;
            transaction.commit()?;
        }
        {
            let mut transaction = project.transaction("test");
            transaction.replace_derived_references(
                coverage,
                ReferenceKind::Data,
                ReferenceProvenance::Function(FunctionId::default()),
                [Reference::data(source, target, ReferenceProperties::READ)],
            )?;
            transaction.commit()?;
        }

        let stored = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("derived replacement must preserve the asserted reference");
        assert!(stored.origin().is_asserted());
        assert!(stored.is_write());
        assert!(!stored.is_read());
        Ok(())
    }

    #[test]
    fn project_materialisation_replaces_derived_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let load = pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;
        let copy = pcode_copy_ir(function, source)?;

        let changes = {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, load.clone())?;
            transaction.commit()?
        };

        let reference = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("materialising PCode should install a derived data reference");
        assert!(reference.is_read());
        assert!(reference.origin().is_derived());

        let incoming = project
            .references
            .references_to(ReferenceTarget::from(target), None)?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            incoming
                .iter()
                .any(|reference| reference.from() == source && reference.is_read()),
            "inverse query should observe the flushed data reference"
        );

        assert!(
            changes
                .records()
                .contains(&ChangeRecord::ReferencesChanged {
                    coverage: {
                        let mut coverage = AddressRangeSet::new();
                        coverage.insert_range(AddressRange::point(source));
                        coverage
                    },
                })
        );

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, copy.clone())?;
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(reference_key(source, target, ReferenceKind::Data))?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn rejecting_materialised_references_preserves_the_previous_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let load = pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;
        let store = pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Store)?;

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, load.clone())?;
            transaction.commit()?;
        }

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, store)?;
            drop(transaction);
        }

        let reference = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("rejection should preserve the previous derived reference");
        assert!(reference.is_read());
        assert!(!reference.is_write());

        Ok(())
    }

    #[test]
    fn project_ecode_materialise_preserves_flushed_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let function = FunctionId::default();
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let target_space = AddressSpaceId::new(2);
        let target = Address::new(target_space, 0x4000u64);
        let pcode = pcode_reference_ir(function, source, target_space, 0x4000, PCodeOpcode::Load)?;

        {
            let mut transaction = project.transaction("test");
            stage_pcode_with_references(&mut transaction, pcode.clone())?;
            transaction.commit()?;
        }

        let pcode = project
            .pcode(function)?
            .expect("pcode should be materialised");
        let ecode = lift_test_ecode(&pcode)?;

        {
            let mut transaction = project.transaction("test");
            transaction.replace_lifted(ecode.clone())?;
            transaction.commit()?;
        }

        let reference = project
            .references
            .get(reference_key(source, target, ReferenceKind::Data))?
            .expect("ecode publication should not remove PCode-derived references");
        assert!(reference.is_read());
        assert!(reference.origin().is_derived());

        Ok(())
    }

    fn flow_resolved_load_function(
        entry: Address,
        data_offset: u64,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = RawPCodeOp {
            op: Op::Load(language.default_space()),
            inputs: Inputs::one(Varnode::constant(data_offset, 8)),
            output: Varnode::new(language.register_space(), 0, 8),
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, 1, &operations)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(IncompleteCodeBlock::new(
            entry,
            1,
            vec![insn],
            ContextSet::default(),
        ));

        Ok(function)
    }

    fn calling_function(
        entry: Address,
        callee: Address,
        size: usize,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let language = resolve_language("x86:LE:64")?;
        let operation = RawPCodeOp {
            op: Op::Call,
            inputs: Inputs::one(Varnode::new(language.default_space(), callee.offset(), 8)),
            output: Varnode::INVALID,
        };
        let operations = [operation];
        let insn = Insn::from_resolved_flow(language, entry, size, &operations)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(
            IncompleteCodeBlock::try_new(entry, size, vec![insn], ContextSet::default())
                .expect("test block size must be valid"),
        );

        Ok(function)
    }

    fn disassembled_function(
        entry: Address,
        size: usize,
    ) -> Result<IncompleteFunction, Box<dyn std::error::Error>> {
        let insn = Insn::from_disassembly(entry, size, InsnProperties::NEEDS_FLOW_RESOLUTION)?;
        let mut function = IncompleteFunction::new(entry);

        let insn = match function.insn_entry(entry) {
            InsnEntry::Vacant(entry) => entry.insert(insn),
            InsnEntry::Occupied(_) => {
                return Err(io::Error::other("test instruction unexpectedly occupied").into());
            }
        };

        function.push_block(
            IncompleteCodeBlock::try_new(entry, size, vec![insn], ContextSet::default())
                .expect("test block size must be valid"),
        );

        Ok(function)
    }

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

    #[test]
    fn project_removing_function_removes_its_switches() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let target = Address::new(AddressSpaceId::new(1), 0x3000u64);
        let default = Address::new(AddressSpaceId::new(1), 0x3500u64);

        let (function_id, changes) = {
            let mut transaction = project.transaction("test");
            let function_id =
                transaction.add_function(flow_resolved_load_function(entry, 0x4000)?)?;
            transaction.add_switch(entry, |id, branch| {
                let mut switch = Switch::new(id, branch, SwitchModel::Explicit);
                switch.add_case(SwitchCase::new(AddressWithContext::new(
                    target,
                    ContextSet::default(),
                )));
                switch
            })?;
            assert!(
                transaction
                    .modify_switch(entry, |switch| {
                        switch.set_default_case(SwitchCase::new(AddressWithContext::new(
                            default,
                            ContextSet::default(),
                        )));
                    })?
                    .is_some()
            );
            let changes = transaction.commit()?;
            (function_id, changes)
        };

        let switch = project
            .switches()
            .get_by_branch(entry)
            .expect("switch present");
        assert_eq!(switch.function(), function_id);
        for destination in [target, default] {
            let reference =
                project
                    .references()
                    .get(reference_key(entry, destination, ReferenceKind::Flow))?;
            assert!(reference.is_some_and(|reference| reference.origin().is_derived()));
        }
        assert_eq!(
            changes
                .records()
                .iter()
                .filter(|record| {
                    matches!(record, ChangeRecord::SwitchAdded { branch } if *branch == entry)
                })
                .count(),
            1
        );

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_function_by_id(function_id, ReferenceOrigin::Derived)?);
            transaction.commit()?;
        }

        assert!(project.switches().get_by_branch(entry).is_none());
        for destination in [target, default] {
            assert!(
                project
                    .references
                    .get(reference_key(entry, destination, ReferenceKind::Flow))?
                    .is_none()
            );
        }
        Ok(())
    }

    #[test]
    fn project_removing_switch_preserves_function_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::new(AddressSpaceId::new(1), 0x2000u64);
        let target = Address::new(AddressSpaceId::new(1), 0x3000u64);

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(calling_function(entry, target, 1)?)?;
            transaction.add_switch(entry, |id, branch| {
                let mut switch = Switch::new(id, branch, SwitchModel::Explicit);
                switch.add_case(SwitchCase::new(AddressWithContext::new(
                    target,
                    ContextSet::default(),
                )));
                switch
            })?;
            transaction.commit()?;
        }

        {
            let reference = project
                .references()
                .get(reference_key(entry, target, ReferenceKind::Flow))?
                .expect("function and switch must derive a shared reference");
            assert!(reference.is_call());
            assert!(reference.is_jump());
            assert!(reference.is_computed());
        }

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_switch(entry)?);
            transaction.commit()?;
        }

        let reference = project
            .references()
            .get(reference_key(entry, target, ReferenceKind::Flow))?
            .expect("removing the switch must preserve the function reference");
        assert!(reference.is_call());
        assert!(!reference.is_jump());
        assert!(!reference.is_computed());

        Ok(())
    }

    #[test]
    fn project_function_add_does_not_materialise_flow_resolved_data_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = Address::new(AddressSpaceId::new(7), 0x1000u64);
        let data_offset = 0x4000u64;
        let target = Address::new(entry.space(), data_offset);
        let function = flow_resolved_load_function(entry, data_offset)?;

        {
            let mut transaction = project.transaction("test");
            transaction.add_function(function)?;
            transaction.commit()?;
        }

        assert!(
            project
                .references()
                .get(reference_key(entry, target, ReferenceKind::Data))?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_preserves_flow_references() -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;
        let bytes = [0x48, 0x89, 0xd8];
        let callee = entry
            .checked_add(0x40u64)
            .ok_or_else(|| io::Error::other("callee address overflow"))?;
        let function = calling_function(entry, callee, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        let flow = project
            .references()
            .get(reference_key(entry, callee, ReferenceKind::Flow))?
            .expect("function add should derive the call flow reference");
        assert!(flow.is_call());

        let engine = AnalysisEngine::new(project)?;
        engine.ensure_lifted(function, PCodeIr::FORM)?;
        let reader = engine.query_reader()?;
        let project = reader.project()?;
        let preserved = project
            .references()
            .get(reference_key(entry, callee, ReferenceKind::Flow))?
            .expect("materialising PCode should preserve the call flow reference");
        assert!(preserved.is_call());

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_builds_from_recovered_instruction_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;
        let bytes = [0x48, 0x89, 0xd8];
        let function = disassembled_function(entry, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        let engine = AnalysisEngine::new(project)?;
        let materialised_pcode = engine.ensure_lifted(function, PCodeIr::FORM)?;
        let materialised_ecode = engine.ensure_lifted(function, ECodeIr::FORM)?;
        let reader = engine.query_reader()?;
        let project = reader.project()?;
        let pcode = project
            .pcode(function)?
            .expect("PCode should be materialised");
        let ecode = project
            .ecode(function)?
            .expect("ECode should be materialised");

        assert!(
            materialised_pcode
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    form: PCodeIr::FORM,
                })
        );
        assert!(
            materialised_ecode
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    form: ECodeIr::FORM,
                })
        );
        assert!(!pcode.ops().is_empty());
        assert_eq!(pcode.source_spans().len(), 1);
        assert_eq!(pcode.source_spans()[0].address(), entry);
        assert!(
            ecode
                .ops()
                .iter()
                .any(|operation| operation.opcode() == ECodeOpcode::WriteRegister)
        );

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_records_zero_operation_source_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;
        let bytes = [0x90];
        let function = disassembled_function(entry, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        let engine = AnalysisEngine::new(project)?;
        engine.ensure_lifted(function, PCodeIr::FORM)?;
        let reader = engine.query_reader()?;
        let project = reader.project()?;
        let pcode = project
            .pcode(function)?
            .expect("PCode should be materialised");
        let source_spans = pcode.source_spans();

        assert!(pcode.ops().is_empty());
        assert_eq!(source_spans.len(), 1);
        assert_eq!(source_spans[0].address(), entry);
        assert!(source_spans[0].destination().is_empty());
        assert_eq!(source_spans[0].source_count(), 0);

        Ok(())
    }

    #[test]
    fn project_ensure_pcode_resolves_default_space_load() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut project = Project::from_file_transient("tests/ls.elf")?;
        let entry = writable_address(&project, 1)?;
        let bytes = [0x48, 0x8b, 0x03];
        let function = disassembled_function(entry, bytes.len())?;
        let function = {
            let mut transaction = project.transaction("test");
            transaction.write_bytes(entry, &bytes)?;
            let function = transaction.add_function(function)?;
            transaction.commit()?;
            function
        };

        let engine = AnalysisEngine::new(project)?;
        let changes = engine.ensure_lifted(function, PCodeIr::FORM)?;
        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedMaterialised {
                    function,
                    form: PCodeIr::FORM,
                })
        );
        let reader = engine.query_reader()?;
        let project = reader.project()?;
        let pcode = project.pcode(function)?.expect("PCode is materialised");
        let load = pcode
            .ops()
            .iter()
            .find(|operation| operation.opcode() == PCodeOpcode::Load)
            .expect("load survives canonicalisation");
        assert_eq!(load.address_space(), Some(entry.space()));

        Ok(())
    }
}
