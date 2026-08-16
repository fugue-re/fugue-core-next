use super::*;
use crate::engine::AnalysisEngine;

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
fn derived_replacement_preserves_an_asserted_reference() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
    let target = Address::new(AddressSpaceId::new(1), 0x2000u64);
    let mut coverage = AddressRangeSet::new();
    coverage.insert_range(AddressRange::point(source));

    {
        let mut transaction = project.transaction("test");
        transaction.add_reference(Reference::data(source, target, ReferenceProperties::WRITE))?;
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
fn rejecting_switch_insertion_discards_the_switch() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let branch = Address::new(AddressSpaceId::new(1), 0x1000u64);

    {
        let mut transaction = project.transaction("test");
        transaction.add_switch(branch, |id, branch| {
            Switch::new(id, branch, SwitchModel::Explicit)
        })?;
        assert!(transaction.switch_at(branch).is_some());
        drop(transaction);
    }

    assert!(project.switches().get_by_branch(branch).is_none());
    Ok(())
}

#[test]
fn project_removing_function_removes_its_switches() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = Address::new(AddressSpaceId::new(1), 0x2000u64);
    let target = Address::new(AddressSpaceId::new(1), 0x3000u64);
    let default = Address::new(AddressSpaceId::new(1), 0x3500u64);

    let (function_id, changes) = {
        let mut transaction = project.transaction("test");
        let function_id = transaction.add_function(flow_resolved_load_function(entry, 0x4000)?)?;
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
            .references
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
            .references
            .get(entry, ReferenceTarget::from(target))?
            .is_none()
    );

    Ok(())
}

#[test]
fn project_ensure_pcode_preserves_flow_references() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
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
        .references
        .get(entry, ReferenceTarget::from(callee))?
        .expect("function add should derive the call flow reference");
    assert!(flow.is_call());

    let engine = AnalysisEngine::new(project)?;
    engine.ensure_lifted(function, PCodeIr::FORM)?;
    let reader = engine.query_reader()?;
    let project = reader.project()?;
    let preserved = project
        .references
        .get(entry, ReferenceTarget::from(callee))?
        .expect("materialising PCode should preserve the call flow reference");
    assert!(preserved.is_call());

    Ok(())
}

#[test]
fn project_ensure_pcode_builds_from_recovered_instruction_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
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
    assert!(!pcode.operations().is_empty());
    assert_eq!(pcode.source_spans().len(), 1);
    assert_eq!(pcode.source_spans()[0].address(), entry);
    assert!(
        ecode
            .operations()
            .iter()
            .any(|operation| operation.opcode() == ECodeOpcode::WriteRegister)
    );

    Ok(())
}

#[test]
fn project_ensure_pcode_records_zero_operation_source_gap() -> Result<(), Box<dyn std::error::Error>>
{
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
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

    assert!(pcode.operations().is_empty());
    assert_eq!(source_spans.len(), 1);
    assert_eq!(source_spans[0].address(), entry);
    assert!(source_spans[0].destination().is_empty());
    assert_eq!(source_spans[0].source_count(), 0);

    Ok(())
}

#[test]
fn project_ensure_pcode_resolves_default_space_load() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
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
        .operations()
        .iter()
        .find(|operation| operation.opcode() == PCodeOpcode::Load)
        .expect("load survives canonicalisation");
    assert_eq!(load.address_space(), Some(entry.space()));

    Ok(())
}

#[test]
fn project_ecode_materialise_preserves_flushed_references() -> Result<(), Box<dyn std::error::Error>>
{
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
