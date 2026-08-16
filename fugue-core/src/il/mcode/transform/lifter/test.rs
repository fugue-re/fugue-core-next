use super::*;

#[test]
fn branch_heavy_rename_state_restores_each_domain_between_siblings() {
    const BRANCH_COUNT: usize = 64;

    let variable = MCodeVarId::try_from_index(0).unwrap();
    let memory_space = AddressSpaceId::new(1);
    let other_space = AddressSpaceId::new(2);
    let output_register = RegisterId::new(3);
    let other_register = RegisterId::new(4);
    let stack_value = IlValueId::try_from_index(0).unwrap();
    let memory_value = IlValueId::try_from_index(1).unwrap();
    let output_value = IlValueId::try_from_index(2).unwrap();
    let mut state = ECodeToMCodeRenameState::default();
    state.insert_stack(variable, stack_value);
    state.insert_memory(memory_space, memory_value);
    state.insert_unmatched_call_memory(memory_space);
    state.insert_unmatched_call_output(output_register, output_value);

    for branch in 0..BRANCH_COUNT {
        let checkpoint = state.checkpoint();
        let branch_value = IlValueId::try_from_index(branch + 3).unwrap();
        state.insert_stack(variable, branch_value);
        state.clear_memory();
        state.insert_memory(other_space, branch_value);
        state.clear_unmatched_call_memory();
        state.insert_unmatched_call_memory(other_space);
        state.clear_unmatched_call_outputs();
        state.insert_unmatched_call_output(other_register, branch_value);
        state.rollback(checkpoint);

        assert_eq!(state.stack_value(variable), Some(stack_value));
        assert_eq!(state.memory_value(memory_space), Some(memory_value));
        assert_eq!(state.memory_value(other_space), None);
        assert!(state.unmatched_call_memory.contains(&memory_space));
        assert!(!state.unmatched_call_memory.contains(&other_space));
        assert_eq!(
            state.unmatched_call_outputs.get(&output_register),
            Some(&output_value)
        );
        assert!(!state.unmatched_call_outputs.contains_key(&other_register));
    }
}
