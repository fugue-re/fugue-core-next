use super::*;

#[test]
fn replacing_function_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = Address::from(0x4000u64);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(tagged_pcode(function, &[1]))?;
        transaction.replace_lifted(ecode_for_test(function, IlGraph::default()))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        assert_eq!(
            transaction.add_function(incomplete_function(entry, 2))?,
            function
        );
        transaction.commit()?
    };

    assert!(project.pcode(function)?.is_none());
    assert!(project.ecode(function)?.is_none());
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        form: PCodeIr::FORM,
    }));
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        form: ECodeIr::FORM,
    }));

    Ok(())
}

#[test]
fn rejecting_function_replacement_preserves_lifted_ir() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = Address::from(0x4000u64);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let materialised = tagged_pcode(function, &[1]);

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(materialised.clone())?;
        transaction.commit()?;
    }
    let materialised = project
        .pcode(function)?
        .expect("materialised PCode should be readable");

    {
        let mut transaction = project.transaction("test");
        transaction.add_function(incomplete_function(entry, 2))?;
        drop(transaction);
    }

    assert_eq!(project.pcode(function)?, Some(materialised));

    let block = project
        .functions()
        .get_by_id(function)
        .and_then(|function| function.blocks().next().map(|(_, block)| block))
        .and_then(|block| project.blocks().get_by_id(block))
        .expect("function body should be restored");
    assert_eq!(block.size(), 1);

    Ok(())
}

#[test]
fn rejecting_function_replacement_preserves_call_graph() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = Address::from(0x4000u64);
    let old_callee = Address::from(0x5000u64);
    let new_callee = Address::from(0x6000u64);

    {
        let mut transaction = project.transaction("test");
        transaction.add_function(calling_function(entry, old_callee, 1)?)?;
        transaction.commit()?;
    }

    assert_eq!(
        project
            .call_graph
            .callees(entry, None)?
            .collect::<Result<Vec<_>, _>>()?,
        vec![old_callee]
    );

    {
        let mut transaction = project.transaction("test");
        transaction.add_function(calling_function(entry, new_callee, 1)?)?;
        assert_eq!(transaction.function_callees(entry)?, vec![new_callee]);
        drop(transaction);
    }

    assert_eq!(
        project
            .call_graph
            .callees(entry, None)?
            .collect::<Result<Vec<_>, _>>()?,
        vec![old_callee]
    );

    Ok(())
}

#[test]
fn removing_function_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = Address::from(0x4000u64);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(tagged_pcode(function, &[1]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_function_by_id(function, ReferenceOrigin::Derived)?);
        transaction.commit()?
    };

    assert!(project.pcode(function)?.is_none());
    assert!(project.functions().get_by_address(entry).is_none());
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        form: PCodeIr::FORM,
    }));
    assert!(changes.records().iter().any(|record| {
        matches!(
            record,
            ChangeRecord::FunctionRemoved {
                entry: removed, ..
            } if *removed == entry
        )
    }));

    Ok(())
}

#[test]
fn byte_write_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 2))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(tagged_pcode(function, &[1]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry + 1u64, &[0xa5])?;
        transaction.commit()?
    };

    assert!(project.pcode(function)?.is_none());
    assert!(project.functions().get_by_address(entry).is_none());
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        form: PCodeIr::FORM,
    }));
    assert!(changes.records().iter().any(|record| {
        matches!(
            record,
            ChangeRecord::FunctionRemoved {
                entry: removed, ..
            } if *removed == entry
        )
    }));

    Ok(())
}

#[test]
fn byte_write_preserves_asserted_function_with_problem() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;

    {
        let mut transaction = project.transaction("test");
        transaction
            .add_function(incomplete_function(entry, 2).with_origin(ReferenceOrigin::Asserted))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry + 1u64, &[0xa5])?;
        transaction.commit()?
    };

    assert!(
        project
            .functions()
            .get_by_address(entry)
            .is_some_and(|function| function.is_asserted())
    );
    assert!(
        project
            .problems()
            .get(entry, ProblemKind::HinderedByAssertedFact)
            .is_some()
    );
    assert!(
        changes
            .records()
            .iter()
            .all(|record| !matches!(record, ChangeRecord::FunctionRemoved { .. }))
    );

    Ok(())
}

#[test]
fn byte_write_invalidates_lifted_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 2))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(tagged_pcode(function, &[1]))?;
        transaction.replace_lifted(ecode_for_test(function, IlGraph::default()))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry + 1u64, &[0xa5])?;
        transaction.commit()?
    };

    assert!(project.pcode(function)?.is_none());
    assert!(project.ecode(function)?.is_none());
    for form in [PCodeIr::FORM, ECodeIr::FORM] {
        assert!(
            changes
                .records()
                .contains(&ChangeRecord::LiftedRemoved { function, form })
        );
    }

    Ok(())
}

#[test]
fn symbol_rename_preserves_lifted() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 250);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 2))?;
        transaction.add_symbol(
            index,
            SymbolEntry::new(entry, "old_display_name", SymbolProperties::FUNCTION),
        )?;
        transaction.commit()?;
        function
    };

    let pcode = tagged_pcode(function, &[1]);
    let ecode = ecode_for_test(function, IlGraph::default());

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(pcode.clone())?;
        transaction.replace_lifted(ecode.clone())?;
        transaction.commit()?;
    }
    let pcode = project
        .pcode(function)?
        .expect("materialised PCode should be readable");
    let ecode = project
        .ecode(function)?
        .expect("materialised ECode should be readable");

    let semantic_revision = project.semantic_revision();
    let changes = {
        let mut transaction = project.transaction("test");
        transaction.add_symbol(
            index,
            SymbolEntry::new(entry, "new_display_name", SymbolProperties::FUNCTION),
        )?;
        transaction.commit()?
    };

    assert_eq!(project.semantic_revision(), semantic_revision);
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
    );
    assert_eq!(project.pcode(function)?, Some(pcode));
    assert_eq!(project.ecode(function)?, Some(ecode));

    Ok(())
}

#[test]
fn reference_edits_preserve_lifted() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
    let target = entry + 0x10u64;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 2))?;
        transaction.commit()?;
        function
    };

    let pcode = tagged_pcode(function, &[1]);
    let ecode = ecode_for_test(function, IlGraph::default());

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(pcode.clone())?;
        transaction.replace_lifted(ecode.clone())?;
        transaction.commit()?;
    }
    let pcode = project
        .pcode(function)?
        .expect("materialised PCode should be readable");
    let ecode = project
        .ecode(function)?
        .expect("materialised ECode should be readable");

    let semantic_revision = project.semantic_revision();
    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.add_reference(Reference::data(
            entry,
            target,
            ReferenceProperties::READ
        ))?);
        transaction.commit()?
    };

    assert_eq!(project.semantic_revision(), semantic_revision);
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
    );

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_reference(entry, ReferenceTarget::from(target))?);
        transaction.commit()?
    };

    assert_eq!(project.semantic_revision(), semantic_revision);
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::LiftedRemoved { .. }))
    );
    assert_eq!(project.pcode(function)?, Some(pcode));
    assert_eq!(project.ecode(function)?, Some(ecode));

    Ok(())
}

#[test]
fn rejecting_byte_write_preserves_lifted_ir() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let materialised = tagged_pcode(function, &[1]);

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(materialised.clone())?;
        transaction.commit()?;
    }
    let materialised = project
        .pcode(function)?
        .expect("materialised PCode should be readable");

    {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry, &[0xa5])?;
        drop(transaction);
    }

    assert_eq!(project.pcode(function)?, Some(materialised));

    Ok(())
}

#[test]
fn mapping_removal_invalidates_lifted() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let (space, mapping, range) = first_mapping_placement(&project);
    let entry = Address::new(space, range.0);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(tagged_pcode(function, &[1]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.remove_mapping(mapping)?;
        transaction.commit()?
    };

    assert!(project.pcode(function)?.is_none());
    assert!(project.functions().get_by_address(entry).is_none());
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        form: PCodeIr::FORM,
    }));
    assert!(changes.records().iter().any(|record| {
        matches!(
            record,
            ChangeRecord::FunctionRemoved {
                entry: removed, ..
            } if *removed == entry
        )
    }));

    Ok(())
}

#[test]
fn rejecting_mapping_removal_preserves_lifted_ir() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let (space, mapping, range) = first_mapping_placement(&project);
    let entry = Address::new(space, range.0);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let materialised = tagged_pcode(function, &[1]);

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(materialised.clone())?;
        transaction.commit()?;
    }
    let materialised = project
        .pcode(function)?
        .expect("materialised PCode should be readable");

    {
        let mut transaction = project.transaction("test");
        transaction.remove_mapping(mapping)?;
        drop(transaction);
    }

    assert_eq!(project.pcode(function)?, Some(materialised));

    Ok(())
}

#[test]
fn mapping_remap_invalidates_old_and_new_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let (space, mapping, old_range) = first_mapping_placement(&project);
    let old_entry = Address::new(space, old_range.0);
    let new_start = project
        .segments()
        .mapping(mapping)
        .expect("mapping should exist")
        .start()
        + 0x1000000u64;
    let new_entry = Address::new(space, new_start.raw_address());

    let (old_function, new_function) = {
        let mut transaction = project.transaction("test");
        let old_function = transaction.add_function(incomplete_function(old_entry, 1))?;
        let new_function = transaction.add_function(incomplete_function(new_entry, 1))?;
        transaction.commit()?;
        (old_function, new_function)
    };

    {
        let mut transaction = project.transaction("test");
        transaction.replace_lifted(tagged_pcode(old_function, &[1]))?;
        transaction.replace_lifted(tagged_pcode(new_function, &[2]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.remap_mapping(mapping, new_start)?;
        transaction.commit()?
    };

    assert!(project.pcode(old_function)?.is_none());
    assert!(project.pcode(new_function)?.is_none());
    assert!(project.functions().get_by_address(old_entry).is_none());
    assert!(project.functions().get_by_address(new_entry).is_none());
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function: old_function,
        form: PCodeIr::FORM,
    }));
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function: new_function,
        form: PCodeIr::FORM,
    }));

    Ok(())
}
