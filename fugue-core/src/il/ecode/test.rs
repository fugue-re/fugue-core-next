use std::mem::size_of;

use super::{ECodeBlockArg, ECodeBuilder, ECodeOp, ECodeOpSpec, ECodeOpcode, ECodeValue};
use crate::analysis::control::CancellationToken;
use crate::il::common::{IlError, IlGraph, IlMetadata, IlValueId};
use crate::ir::FunctionId;

pub(crate) fn emit_value(
    builder: &mut ECodeBuilder,
    spec: ECodeOpSpec,
    operands: impl IntoIterator<Item = IlValueId>,
) -> Result<IlValueId, IlError> {
    let (_, results) = builder.emitter().emit(spec, operands, 1)?;
    IlValueId::try_from_index(results.start())
}

#[test]
fn ecode_records_stay_compact() {
    assert!(size_of::<ECodeValue>() <= 12);
    assert!(size_of::<ECodeBlockArg>() <= 12);
    assert!(size_of::<ECodeOp>() <= 64);
}

#[test]
fn exact_insert_extract_pair_recovers_only_the_inserted_value() {
    let metadata = IlMetadata::new(FunctionId::default(), 0);
    let mut builder = ECodeBuilder::new(metadata, IlGraph::default());

    let base = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
        [],
    )
    .unwrap();
    let inserted = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Undefined, 32),
        [],
    )
    .unwrap();
    let combined = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Insert, 64).with_immediate(8),
        [base, inserted],
    )
    .unwrap();
    let exact = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Extract, 32).with_immediate(8),
        [combined],
    )
    .unwrap();
    let narrow = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Extract, 8).with_immediate(8),
        [combined],
    )
    .unwrap();
    let shifted = emit_value(
        &mut builder,
        ECodeOpSpec::new(ECodeOpcode::Extract, 32),
        [combined],
    )
    .unwrap();

    let ir = builder.build(&CancellationToken::default()).unwrap();

    assert_eq!(ir.extract_source(exact), Some(inserted));
    assert_eq!(ir.extract_source(narrow), None);
    assert_eq!(ir.extract_source(shifted), Some(combined));
    assert_eq!(ir.underlying_value(exact), exact);
}
