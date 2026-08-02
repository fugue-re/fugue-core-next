use super::*;

#[test]
fn rejecting_lifted_removal_preserves_materialised_ir() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let function = FunctionId::default();
    let materialised = tagged_pcode(function, &[1, 2, 3]);

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.materialise_lifted(materialised.clone())?;
        transaction.commit()?
    };

    assert!(
        changes
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                level: IlLevel::PCode,
            })
    );
    assert_eq!(project.pcode(function)?.as_ref(), Some(&materialised));

    {
        let mut transaction = project.transaction("test");
        transaction.materialise_lifted(tagged_pcode(function, &[4, 5, 6]))?;
        drop(transaction);
    }

    assert_eq!(project.pcode(function)?.as_ref(), Some(&materialised));

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_lifted(function, IlLevel::PCode)?);
        transaction.commit()?
    };

    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        level: IlLevel::PCode,
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
        transaction.materialise_lifted(body.clone())?;
        transaction.commit()?;
    }

    let read = project
        .pcode(FunctionId::default())?
        .expect("PCode IR should be materialised");

    assert_eq!(read.operations(), body.operations());
    assert_eq!(
        read.metadata().input_revision(),
        project.semantic_revision()
    );

    Ok(())
}

#[test]
fn project_reads_ecode_ssa_derived_tables() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let function = FunctionId::default();

    {
        let mut transaction = project.transaction("test");
        transaction.materialise_lifted(pcode_for_test(function, single_block_graph()))?;
        transaction.materialise_lifted(ecode_for_test(function, single_block_graph()))?;
        transaction.materialise_lifted(ecode_ssa_for_test(function, single_block_graph()))?;
        transaction.commit()?;
    }

    let entry = IlBlockId::try_from_index(0)?;
    let value = IlValueId::try_from_index(0)?;
    let ir = project
        .ecode_ssa(function)?
        .expect("SSA IR should be available");
    let uses = ir.analyse::<ECodeSsaUses>();
    let dominance = ir.analyse::<IlDominance>();
    let frontiers = dominance.frontiers(ir.graph().blocks(), ir.graph().successors());
    let liveness = ir.analyse::<ECodeSsaLiveness>();

    assert!(uses.uses_for(value).is_empty());
    assert!(dominance.dominates(entry, entry));
    assert!(frontiers.frontier_for(entry).is_empty());
    assert!(liveness.live_in(entry).is_empty());
    assert!(liveness.live_out(entry).is_empty());

    Ok(())
}

#[test]
fn ensure_lifted_builds_ecode_from_pcode() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
    let function = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry, &[0x90])?;
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let body = pcode_for_test(function, IlGraph::default());

    {
        let mut transaction = project.transaction("test");
        transaction.materialise_lifted(body)?;
        transaction.commit()?;
    }
    assert!(project.pcode(function)?.is_some());

    let engine = AnalysisEngine::new(project)?;
    let changes = engine.ensure_lifted(function, IlLevel::ECode)?;
    let reader = engine.query_reader()?;
    assert!(reader.pcode(function)?.is_some());
    assert!(reader.ecode(function)?.is_some());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                level: IlLevel::ECode,
            })
    );

    let changes = engine.ensure_lifted(function, IlLevel::ECode)?;

    assert!(changes.records().is_empty());

    Ok(())
}

#[test]
fn ensure_lifted_builds_ssa_through_ecode() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)?;
    let function = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry, &[0x90])?;
        let function = transaction.add_function(incomplete_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let body = pcode_for_test(function, IlGraph::default());

    {
        let mut transaction = project.transaction("test");
        transaction.materialise_lifted(body)?;
        transaction.commit()?;
    }

    let engine = AnalysisEngine::new(project)?;
    let changes = engine.ensure_lifted(function, IlLevel::ECodeSsa)?;
    let reader = engine.query_reader()?;
    assert!(reader.ecode(function)?.is_some());
    assert!(reader.ecode_ssa(function)?.is_some());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                level: IlLevel::ECode,
            })
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                level: IlLevel::ECodeSsa,
            })
    );

    Ok(())
}

#[test]
fn lifted_descendant_removal_preserves_parent() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let function = FunctionId::default();

    {
        let mut transaction = project.transaction("test");
        transaction.materialise_lifted(tagged_pcode(function, &[1]))?;
        transaction.materialise_lifted(ecode_for_test(function, IlGraph::default()))?;
        transaction.materialise_lifted(ecode_ssa_for_test(function, IlGraph::default()))?;
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        assert_eq!(transaction.remove_lifted_from(function, IlLevel::ECode)?, 2);
        drop(transaction);
    }

    assert!(project.ecode(function)?.is_some());
    assert!(project.ecode_ssa(function)?.is_some());

    let changes = {
        let mut transaction = project.transaction("test");
        assert_eq!(transaction.remove_lifted_from(function, IlLevel::ECode)?, 2);
        transaction.commit()?
    };

    assert!(project.pcode(function)?.is_some());
    assert!(project.ecode(function)?.is_none());
    assert!(project.ecode_ssa(function)?.is_none());
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        level: IlLevel::ECode,
    }));
    assert!(changes.records().contains(&ChangeRecord::LiftedRemoved {
        function,
        level: IlLevel::ECodeSsa,
    }));

    Ok(())
}
