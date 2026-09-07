use std::collections::{BTreeMap, BTreeSet};
use std::iter;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use super::{ProjectTransaction, StagedReferenceRecord};
use crate::ir::{
    Address, AddressRange, AddressRangeSet, Reference, ReferenceIndex, ReferenceKey, ReferenceKind,
    ReferenceOrigin, ReferenceTarget,
};
use crate::project::ProjectError;

pub(crate) struct DerivedReferenceBatch {
    coverage: AddressRangeSet,
    kind: ReferenceKind,
    references: Vec<Reference>,
}

impl DerivedReferenceBatch {
    pub(crate) fn new(
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        references: impl IntoIterator<Item = Reference>,
    ) -> Self {
        Self {
            coverage,
            kind,
            references: references
                .into_iter()
                .map(|reference| reference.with_origin(ReferenceOrigin::Derived))
                .collect(),
        }
    }
}

impl ProjectTransaction<'_> {
    pub(crate) fn replace_derived_references(
        &mut self,
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        derived: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        self.replace_derived_reference_batches(iter::once(DerivedReferenceBatch::new(
            coverage, kind, derived,
        )))
    }

    pub(crate) fn replace_derived_reference_batches(
        &mut self,
        replacements: impl IntoIterator<Item = DerivedReferenceBatch>,
    ) -> Result<bool, ProjectError> {
        let mut replacements = replacements.into_iter().collect::<SmallVec<[_; 4]>>();
        let mut combined_coverage = AddressRangeSet::new();
        for replacement in &mut replacements {
            for reference in &replacement.references {
                replacement
                    .coverage
                    .insert_range(AddressRange::point(reference.from()));
            }
            for range in replacement.coverage.ranges() {
                combined_coverage.insert_range(range);
            }
        }
        if combined_coverage.is_empty() {
            return Ok(false);
        }

        let mut current = self
            .staged_references_in(&combined_coverage)?
            .into_iter()
            .map(|reference| {
                (
                    ReferenceKey::new(reference.from(), reference.target()),
                    reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        if current.is_empty() {
            let mut changed = false;
            for replacement in replacements {
                if replacement.references.is_empty() {
                    continue;
                }
                for reference in replacement.references {
                    let key = ReferenceKey::new(reference.from(), reference.target());
                    self.stage_reference_record(key, None, Some(reference));
                }
                for range in replacement.coverage.ranges() {
                    self.derived_reference_coverage.insert_range(range);
                }
                changed = true;
            }
            return Ok(changed);
        }

        let flow_reference_count = replacements
            .iter()
            .filter(|replacement| replacement.kind.is_flow())
            .map(|replacement| replacement.references.len())
            .sum();
        let mut supported_flow = FxHashMap::<ReferenceKey, Reference>::with_capacity_and_hasher(
            flow_reference_count,
            Default::default(),
        );
        for replacement in &replacements {
            if !replacement.kind.is_flow() {
                continue;
            }
            for &reference in &replacement.references {
                let key = ReferenceKey::new(reference.from(), reference.target());
                supported_flow
                    .entry(key)
                    .and_modify(|supported| {
                        *supported = supported.with_merged_properties(reference.properties());
                    })
                    .or_insert(reference);
            }
        }

        let mut changed = false;

        for replacement in replacements {
            let mut covered = Vec::new();
            for range in replacement.coverage.ranges() {
                let start = ReferenceKey::minimum_for(range.start_address());
                for (&key, &reference) in current.range(start..) {
                    if key.from() > range.end_address() {
                        break;
                    }
                    covered.push(reference);
                }
            }
            if covered.is_empty() {
                if replacement.references.is_empty() {
                    continue;
                }
                for reference in replacement.references {
                    let key = ReferenceKey::new(reference.from(), reference.target());
                    current.insert(key, reference);
                    self.stage_reference_record(key, None, Some(reference));
                }
                for range in replacement.coverage.ranges() {
                    self.derived_reference_coverage.insert_range(range);
                }
                changed = true;
                continue;
            }
            if ReferenceIndex::derived_kind_matches(
                &covered,
                &replacement.references,
                replacement.kind,
            ) {
                continue;
            }

            let mut occupied = BTreeSet::new();
            for reference in covered {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if reference.origin().is_derived() && reference.kind() == replacement.kind {
                    let supported = match supported_flow.get(&key) {
                        Some(&supported) => Some(supported),
                        None if replacement.kind.is_flow() => {
                            self.function_staging.supported_backing_flow_reference(
                                &self.project.functions,
                                &self.project.blocks,
                                reference,
                            )?
                        }
                        None => None,
                    };
                    if let Some(supported) = supported {
                        current.insert(key, supported);
                        if supported != reference {
                            self.stage_reference_record(key, Some(reference), Some(supported));
                        }
                        continue;
                    }
                    current.remove(&key);
                    self.stage_reference_record(key, Some(reference), None);
                } else {
                    occupied.insert(key);
                }
            }
            for reference in replacement.references {
                let key = ReferenceKey::new(reference.from(), reference.target());
                if !occupied.contains(&key) {
                    current.insert(key, reference);
                    self.stage_reference_record(key, None, Some(reference));
                }
            }

            for range in replacement.coverage.ranges() {
                self.derived_reference_coverage.insert_range(range);
            }
            changed = true;
        }

        Ok(changed)
    }

    pub fn add_reference(&mut self, reference: Reference) -> Result<bool, ProjectError> {
        let reference = reference.with_origin(ReferenceOrigin::Asserted);
        let from = reference.from();
        let target = reference.target();

        let key = ReferenceKey::new(from, target);
        let existing = self.staged_reference(key)?;
        let resolved = match existing {
            Some(existing)
                if existing.origin().is_asserted() && existing.kind() == reference.kind() =>
            {
                existing.with_merged_properties(reference.properties())
            }
            _ => reference,
        };

        if let Some(existing) = existing
            && existing.origin().is_asserted()
            && existing.kind() == resolved.kind()
            && existing.properties() == resolved.properties()
        {
            return Ok(false);
        }

        self.stage_reference_record(key, existing, Some(resolved));
        self.asserted_references.insert(key);
        Ok(true)
    }

    pub fn remove_reference(
        &mut self,
        from: Address,
        target: ReferenceTarget,
    ) -> Result<bool, ProjectError> {
        let key = ReferenceKey::new(from, target);
        let Some(previous) = self.staged_reference(key)? else {
            return Ok(false);
        };

        self.stage_reference_record(key, Some(previous), None);
        self.asserted_references.insert(key);
        Ok(true)
    }

    fn stage_reference_record(
        &mut self,
        key: ReferenceKey,
        previous: Option<Reference>,
        reference: Option<Reference>,
    ) {
        if let Some(record) = self.staged_references.get_mut(&key) {
            record.reference = reference;
        } else {
            self.staged_references.insert(
                key,
                StagedReferenceRecord {
                    previous,
                    reference,
                },
            );
        }
    }

    fn staged_reference(&self, key: ReferenceKey) -> Result<Option<Reference>, ProjectError> {
        match self.staged_references.get(&key) {
            Some(record) => Ok(record.reference),
            None => self
                .project
                .references
                .get(key.from(), key.target())
                .map_err(ProjectError::from),
        }
    }

    fn staged_references_in(
        &self,
        coverage: &AddressRangeSet,
    ) -> Result<Vec<Reference>, ProjectError> {
        let mut references = self
            .project
            .references
            .references_in(coverage)?
            .into_iter()
            .map(|reference| {
                (
                    ReferenceKey::new(reference.from(), reference.target()),
                    reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for range in coverage.ranges() {
            let start = ReferenceKey::minimum_for(range.start_address());
            for (&key, record) in self.staged_references.range(start..) {
                if key.from() > range.end_address() {
                    break;
                }
                match record.reference {
                    Some(reference) => {
                        references.insert(key, reference);
                    }
                    None => {
                        references.remove(&key);
                    }
                }
            }
        }
        Ok(references.into_values().collect())
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
        AddressWithContext, FunctionId, IncompleteCodeBlock, IncompleteFunction, Insn, InsnEntry,
        InsnProperties, ReferenceProperties, Switch, SwitchCase, SwitchModel,
    };
    use crate::lifter::{ContextSet, Op, RawPCodeOp, Varnode, resolve_language};
    use crate::project::{ChangeRecord, Project, ProjectTransaction};
    use crate::storage::{AddressSpaceId, DEFAULT_SPACE_ID};

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
        transaction.replace_lifted(pcode)?;
        transaction.replace_derived_references(coverage, ReferenceKind::Data, references)?;
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
                .get(source, ReferenceTarget::from(target))?
                .is_some()
        );

        {
            let mut transaction = project.transaction("test");
            assert!(transaction.remove_lifted::<PCodeIr>(function)?);
            transaction.commit()?;
        }

        let retained = project
            .references
            .get(source, ReferenceTarget::from(target))?
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
            .get(source, ReferenceTarget::from(target))?
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
                [Reference::data(source, target, ReferenceProperties::READ)],
            )?;
            transaction.commit()?;
        }

        let stored = project
            .references
            .get(source, ReferenceTarget::from(target))?
            .expect("derived replacement should insert the reference");
        assert!(stored.origin().is_derived());

        {
            let mut transaction = project.transaction("test");
            transaction.replace_derived_references(coverage, ReferenceKind::Data, [])?;
            transaction.commit()?;
        }

        assert!(
            project
                .references
                .get(source, ReferenceTarget::from(target))?
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
                [Reference::data(source, target, ReferenceProperties::READ)],
            )?;
            transaction.commit()?;
        }

        let stored = project
            .references
            .get(source, ReferenceTarget::from(target))?
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
            .get(source, ReferenceTarget::from(target))?
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
                .get(source, ReferenceTarget::from(target))?
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
            .get(source, ReferenceTarget::from(target))?
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
            .get(source, ReferenceTarget::from(target))?
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
            let reference = project
                .references()
                .get(entry, ReferenceTarget::from(destination))?;
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
                    .get(entry, ReferenceTarget::from(destination))?
                    .is_none()
            );
        }
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
                .get(entry, ReferenceTarget::from(target))?
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
            .get(entry, ReferenceTarget::from(callee))?
            .expect("function add should derive the call flow reference");
        assert!(flow.is_call());

        let engine = AnalysisEngine::new(project)?;
        engine.ensure_lifted(function, PCodeIr::FORM)?;
        let reader = engine.query_reader()?;
        let project = reader.project()?;
        let preserved = project
            .references()
            .get(entry, ReferenceTarget::from(callee))?
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
