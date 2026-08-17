use std::error::Error;
use std::io;

use fugue_core::analysis::control::CancellationToken;
use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
use fugue_core::il::common::{IlOpId, IlValueId, RegisterBank};
use fugue_core::il::ecode::{ECodeDomain, ECodeIr, ECodeOpcode};
use fugue_core::il::mcode::{
    ECodeToMCode, MCodeCallFacts, MCodeFunctionFacts, MCodeIr, MCodeOpcode, MCodeStorageFact,
    MCodeStorageLocation,
};
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
    let mut call_args = false;
    let mut call_outputs = false;
    for function in functions {
        let ecode = reader
            .lifted::<ECodeIr>(function)?
            .ok_or_else(|| io::Error::other("ECode missing after generation"))?;
        entry_stack_pointer |= ecode.values().iter().enumerate().any(|(index, _)| {
            let value = IlValueId::try_from_index(index).expect("value index is representable");
            ecode.value_domain(value) == Some(ECodeDomain::Register(stack_pointer))
                && ecode
                    .defining_operation(value)
                    .is_some_and(|operation| operation.opcode() == ECodeOpcode::Undefined)
        });
        let mcode = reader
            .lifted::<MCodeIr>(function)?
            .ok_or_else(|| io::Error::other("MCode missing after generation"))?;
        assert_eq!(mcode.metadata().function(), function);
        variable_merge |= mcode
            .block_args()
            .iter()
            .any(|arg| mcode.binding(arg.value()).is_some());
        memory_merge |= mcode.block_args().iter().any(|arg| arg.width() == 0);
        for operation in mcode.operations() {
            if operation.opcode() != MCodeOpcode::Call {
                continue;
            }
            call_args |= mcode.operation_operands_for(operation).len() > 1;
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
    assert!(call_args, "fixture contains no recovered call arguments");
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

#[test]
fn an_external_consumer_can_supply_function_scoped_facts() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let arch = project.arch().clone();
    let platform = project.platform().clone();
    let engine = AnalysisEngine::with_config(
        project,
        AnalysisEngineConfig::default().with_worker_limit(1),
    )?;
    engine.analyse()?;
    let reader = engine.query_reader()?;
    let functions = reader
        .project()?
        .functions()
        .iter()
        .map(|function| function.id())
        .collect::<Vec<_>>();
    let (source, site) = functions
        .into_iter()
        .find_map(|function| {
            let source = reader.lifted::<ECodeIr>(function).ok().flatten()?;
            let site = source
                .operations()
                .iter()
                .position(|operation| operation.opcode() == ECodeOpcode::Call)
                .and_then(|index| IlOpId::try_from_index(index).ok())?;
            Some((source, site))
        })
        .ok_or_else(|| io::Error::other("fixture contains no direct ECode call"))?;
    let storage = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64);
    let mut call = MCodeCallFacts::new(site);
    call.insert_input(storage);
    assert_eq!(call.inputs(), Some(&[storage][..]));
    call.set_inputs([]);
    call.set_outputs([]);
    let mut facts = MCodeFunctionFacts::new(source.metadata().function());
    facts.insert_call(call);

    let mcode = ECodeToMCode::default().transform(
        &source,
        &arch,
        &platform,
        Some(&facts),
        &CancellationToken::default(),
    )?;

    assert_eq!(mcode.metadata().function(), facts.function());
    Ok(())
}
