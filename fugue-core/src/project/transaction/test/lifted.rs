use super::*;
use crate::engine::AnalysisEngine;

#[test]
fn rejecting_lifted_removal_preserves_materialised_ir() -> Result<(), Box<dyn std::error::Error>> {
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

    assert_eq!(read.operations(), body.operations());
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
        transaction.replace_lifted(body)?;
        transaction.commit()?;
    }
    assert!(project.pcode(function)?.is_some());

    let engine = AnalysisEngine::new(project)?;
    let changes = engine.ensure_lifted(function, ECodeIr::FORM)?;
    let reader = engine.query_reader()?;
    assert!(reader.pcode(function)?.is_some());
    assert!(reader.ecode(function)?.is_some());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::LiftedMaterialised {
                function,
                form: ECodeIr::FORM,
            })
    );

    let changes = engine.ensure_lifted(function, ECodeIr::FORM)?;

    assert!(changes.records().is_empty());

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
