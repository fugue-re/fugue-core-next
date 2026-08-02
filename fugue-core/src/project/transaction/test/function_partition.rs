use super::*;
use crate::ir::{FlowKind, IncompleteCodeBlockId};
use crate::lifter::ContextBitRange;

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
fn split_and_merge_follow_membership_and_control_flow() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)? + 0x100u64;
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
            .functions_containing_block(shared_block)
            .collect::<Vec<_>>(),
        vec![function, child],
    );
    assert!(
        project
            .references
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
            .references
            .get(split, ReferenceTarget::from(external))?
            .is_some()
    );

    Ok(())
}

#[test]
fn split_uses_block_identity_at_an_ambiguous_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let entry = writable_address(&project)? + 0x200u64;
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
