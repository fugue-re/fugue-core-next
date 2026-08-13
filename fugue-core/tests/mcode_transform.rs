use std::error::Error;
use std::io;

use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::il::common::IlValueId;
use fugue_core::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOpcode};
use fugue_core::il::mcode::ssa::{MCodeSsaIr, MCodeSsaOpcode};
use fugue_core::il::pcode::RegisterBank;
use fugue_core::loader::Loader;
use fugue_core::project::Project;

fn every_recovered_function_lifts(fixture: &str) -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file(fixture)?;
    let project = Project::new_transient(&loader)?;
    let language = project.language();
    let convention = language
        .convention("gcc")
        .or_else(|| language.convention("default"))
        .ok_or_else(|| io::Error::other("fixture has no calling convention"))?;
    let pointer = convention.stack_pointer();
    let stack_pointer = RegisterBank::new(language)?
        .root_id(pointer.offset(), pointer.size())
        .ok_or_else(|| io::Error::other("fixture stack pointer has no register root"))?;
    let config = AnalysisEngineConfig::default().with_worker_limit(1);
    let engine = AnalysisEngine::with_config(project, config)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let functions = reader
        .project()?
        .functions()
        .iter()
        .map(|function| function.id())
        .collect::<Vec<_>>();
    if functions.is_empty() {
        return Err(io::Error::other("fixture contains no recovered functions").into());
    }

    let mut variable_merge = false;
    let mut memory_merge = false;
    let mut entry_stack_pointer = false;
    let mut call_arguments = false;
    let mut call_outputs = false;
    for function in functions {
        let ecode = reader
            .lifted::<ECodeSsaIr>(function)?
            .ok_or_else(|| io::Error::other("ECode SSA missing after generation"))?;
        entry_stack_pointer |= ecode.values().iter().enumerate().any(|(index, _)| {
            let value = IlValueId::try_from_index(index).expect("value index is representable");
            ecode.value_domain(value) == Some(ECodeSsaDomain::Register(stack_pointer))
                && ecode
                    .defining_operation(value)
                    .is_some_and(|operation| operation.opcode() == ECodeSsaOpcode::Undefined)
        });
        let mcode = reader
            .lifted::<MCodeSsaIr>(function)?
            .ok_or_else(|| io::Error::other("MCode SSA missing after generation"))?;
        assert_eq!(mcode.metadata().function(), function);
        variable_merge |= mcode
            .block_arguments()
            .iter()
            .any(|argument| mcode.binding(argument.value()).is_some());
        memory_merge |= mcode
            .block_arguments()
            .iter()
            .any(|argument| argument.width() == 0);
        for operation in mcode.operations() {
            if operation.opcode() != MCodeSsaOpcode::Call {
                continue;
            }
            call_arguments |= mcode.operation_operands_for(operation).len() > 1;
            call_outputs |= operation.results().len() > 1
                && operation
                    .results()
                    .slice(mcode.values())
                    .iter()
                    .skip(1)
                    .all(|value| value.binding().is_some());
        }
    }
    assert!(variable_merge, "fixture contains no variable merge");
    assert!(memory_merge, "fixture contains no memory merge");
    assert!(
        entry_stack_pointer,
        "fixture contains no entry stack pointer"
    );
    assert!(
        call_arguments,
        "fixture contains no recovered call arguments"
    );
    assert!(call_outputs, "fixture contains no bound call outputs");

    Ok(())
}

#[test]
fn every_ls_function_lifts_to_mcode() -> Result<(), Box<dyn Error>> {
    every_recovered_function_lifts("tests/ls.elf")
}

#[test]
fn every_libipmi_function_lifts_to_mcode() -> Result<(), Box<dyn Error>> {
    every_recovered_function_lifts("tests/libipmi.so")
}
