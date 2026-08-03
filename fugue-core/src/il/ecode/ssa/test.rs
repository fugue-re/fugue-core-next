use std::mem::size_of;

use super::{ECodeSsaBlockArg, ECodeSsaBuilder, ECodeSsaOp, ECodeSsaOpcode, ECodeSsaValue};
use crate::analysis::control::CancellationToken;
use crate::il::common::{IlGraph, IlIndexRange, IlMetadata};
use crate::ir::FunctionId;

#[test]
fn ssa_records_stay_compact() {
    assert!(size_of::<ECodeSsaValue>() <= 12);
    assert!(size_of::<ECodeSsaBlockArg>() <= 12);
    assert!(size_of::<ECodeSsaOp>() <= 64);
}

#[test]
fn exact_insert_extract_pair_recovers_only_the_inserted_value() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeSsaBuilder::new(metadata, IlGraph::default());

    let (base, base_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            base_results,
            IlIndexRange::EMPTY,
            64,
        ))
        .unwrap();

    let (inserted, inserted_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Undefined,
            inserted_results,
            IlIndexRange::EMPTY,
            32,
        ))
        .unwrap();

    let insert_operands = builder.push_value_operands([base, inserted]).unwrap();
    let (combined, combined_results) = builder.push_result_value(64).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(
                ECodeSsaOpcode::Insert,
                combined_results,
                insert_operands,
                64,
            )
            .with_immediate(8),
        )
        .unwrap();

    let exact_operands = builder.push_value_operands([combined]).unwrap();
    let (exact, exact_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Extract, exact_results, exact_operands, 32)
                .with_immediate(8),
        )
        .unwrap();

    let narrow_operands = builder.push_value_operands([combined]).unwrap();
    let (narrow, narrow_results) = builder.push_result_value(8).unwrap();
    builder
        .push_operation(
            ECodeSsaOp::new(ECodeSsaOpcode::Extract, narrow_results, narrow_operands, 8)
                .with_immediate(8),
        )
        .unwrap();

    let shifted_operands = builder.push_value_operands([combined]).unwrap();
    let (shifted, shifted_results) = builder.push_result_value(32).unwrap();
    builder
        .push_operation(ECodeSsaOp::new(
            ECodeSsaOpcode::Extract,
            shifted_results,
            shifted_operands,
            32,
        ))
        .unwrap();

    let ssa = builder.build(&CancellationToken::default()).unwrap();

    assert_eq!(ssa.extract_source(exact), Some(inserted));
    assert_eq!(ssa.extract_source(narrow), None);
    assert_eq!(ssa.extract_source(shifted), Some(combined));
    assert_eq!(ssa.underlying_value(exact), exact);
}
