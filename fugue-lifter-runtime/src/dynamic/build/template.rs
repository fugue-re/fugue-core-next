use fugue_sleigh_language::construct::{
    ConstTpl as SleighConstTpl, ConstructTpl as SleighConstructTpl, HandleKind as SleighHandleKind,
    HandleTpl as SleighHandleTpl, OpTpl as SleighOpTpl, VarnodeTpl as SleighVarnodeTpl,
};
use fugue_sleigh_language::opcode::Opcode;
use fugue_sleigh_language::Language as SleighLanguage;

use crate::dynamic::blob;
use crate::dynamic::build::Tables;
use crate::template::{ConstTpl, HandleKind, HandleTpl, Op, VarnodeTpl};

pub(super) fn const_tpl_index<'a>(
    language: &SleighLanguage,
    tpl: &'a SleighConstTpl,
    tables: &mut Tables<'a>,
) -> u16 {
    let value = match tpl {
        SleighConstTpl::Real(val) => ConstTpl::Real(*val),
        SleighConstTpl::Handle(index, kind) => {
            let kind = match kind {
                SleighHandleKind::Space => HandleKind::Space,
                SleighHandleKind::Offset => HandleKind::Offset,
                SleighHandleKind::Size => HandleKind::Size,
                SleighHandleKind::OffsetPlus(val) => HandleKind::OffsetPlus(*val),
            };
            ConstTpl::Handle(*index, kind)
        }
        SleighConstTpl::Start => ConstTpl::Start,
        SleighConstTpl::Next => ConstTpl::Next,
        SleighConstTpl::Next2 => ConstTpl::Next2,
        SleighConstTpl::CurrentSpace => ConstTpl::CurrentSpace,
        SleighConstTpl::CurrentSpaceSize => ConstTpl::CurrentSpaceSize,
        SleighConstTpl::SpaceId(id) => ConstTpl::SpaceId(id.index() as u8),
        SleighConstTpl::Relative(val) => ConstTpl::Relative(*val),
        _ => panic!("flow operations are not supported by the dynamic builder"),
    };

    let _ = language;
    push_const_tpl(tables, tpl, value)
}

pub(super) fn handle_tpl_index<'a>(
    language: &SleighLanguage,
    tpl: &'a SleighHandleTpl,
    tables: &mut Tables<'a>,
) -> u16 {
    let space = const_tpl_index(language, tpl.space(), tables);
    let size = const_tpl_index(language, tpl.size(), tables);
    let ptr_space = const_tpl_index(language, tpl.ptr_space(), tables);
    let ptr_offset = const_tpl_index(language, tpl.ptr_offset(), tables);
    let ptr_size = const_tpl_index(language, tpl.ptr_size(), tables);
    let tmp_space = const_tpl_index(language, tpl.tmp_space(), tables);
    let tmp_offset = const_tpl_index(language, tpl.tmp_offset(), tables);

    push_handle_tpl(
        tables,
        tpl,
        HandleTpl {
            space,
            size,
            ptr_space,
            ptr_offset,
            ptr_size,
            tmp_space,
            tmp_offset,
        },
    )
}

pub(super) fn varnode_tpl_index<'a>(
    language: &SleighLanguage,
    tpl: &'a SleighVarnodeTpl,
    tables: &mut Tables<'a>,
) -> u16 {
    let space = const_tpl_index(language, tpl.space(), tables);
    let offset = const_tpl_index(language, tpl.offset(), tables);
    let size = const_tpl_index(language, tpl.size(), tables);
    push_varnode_tpl(
        tables,
        tpl,
        VarnodeTpl {
            space,
            offset,
            size,
        },
    )
}

pub(super) fn op_tpl_index<'a>(
    language: &SleighLanguage,
    tpl: &'a SleighOpTpl,
    tables: &mut Tables<'a>,
) -> u16 {
    let op = map_opcode(tpl.opcode());
    let inputs = tpl
        .inputs()
        .iter()
        .map(|input| varnode_tpl_index(language, input, tables))
        .collect::<Box<[u16]>>();
    let output = tpl
        .output()
        .map(|out| varnode_tpl_index(language, out, tables));

    push_op_tpl(tables, tpl, blob::template::OpTpl { op, inputs, output })
}

pub(super) fn construct_tpl_index<'a>(
    language: &SleighLanguage,
    tpl: &'a SleighConstructTpl,
    tables: &mut Tables<'a>,
) -> u16 {
    let delay_slot = u8::try_from(tpl.delay_slot()).expect("delay slot fits in u8");
    let labels = u8::try_from(tpl.labels()).expect("labels fits in u8");
    let result = tpl
        .result()
        .map(|res| handle_tpl_index(language, res, tables));
    let operations = tpl
        .operations()
        .iter()
        .map(|op| op_tpl_index(language, op, tables))
        .collect::<Box<[u16]>>();

    push_construct_tpl(
        tables,
        tpl,
        blob::template::ConstructTpl {
            delay_slot,
            labels,
            result,
            operations,
        },
    )
}

fn map_opcode(opcode: Opcode) -> Op {
    use Opcode as O;
    match opcode {
        O::Copy => Op::Copy,
        O::Load => Op::Load,
        O::Store => Op::Store,
        O::Branch => Op::Branch,
        O::CBranch => Op::CBranch,
        O::IBranch => Op::IBranch,
        O::Call => Op::Call,
        O::ICall => Op::ICall,
        O::CallOther => Op::CallOther,
        O::Return => Op::Return,
        O::IntEq => Op::IntEq,
        O::IntNotEq => Op::IntNotEq,
        O::IntSLess => Op::IntSLess,
        O::IntSLessEq => Op::IntSLessEq,
        O::IntLess => Op::IntLess,
        O::IntLessEq => Op::IntLessEq,
        O::IntZExt => Op::IntZExt,
        O::IntSExt => Op::IntSExt,
        O::IntNeg => Op::IntNeg,
        O::IntNot => Op::IntNot,
        O::IntAdd => Op::IntAdd,
        O::IntSub => Op::IntSub,
        O::IntMul => Op::IntMul,
        O::IntDiv => Op::IntDiv,
        O::IntSDiv => Op::IntSDiv,
        O::IntRem => Op::IntRem,
        O::IntSRem => Op::IntSRem,
        O::IntCarry => Op::IntCarry,
        O::IntSCarry => Op::IntSCarry,
        O::IntSBorrow => Op::IntSBorrow,
        O::IntAnd => Op::IntAnd,
        O::IntOr => Op::IntOr,
        O::IntXor => Op::IntXor,
        O::IntLShift => Op::IntLShift,
        O::IntRShift => Op::IntRShift,
        O::IntSRShift => Op::IntSRShift,
        O::BoolNot => Op::BoolNot,
        O::BoolAnd => Op::BoolAnd,
        O::BoolOr => Op::BoolOr,
        O::BoolXor => Op::BoolXor,
        O::FloatEq => Op::FloatEq,
        O::FloatNotEq => Op::FloatNotEq,
        O::FloatLess => Op::FloatLess,
        O::FloatLessEq => Op::FloatLessEq,
        O::FloatIsNaN => Op::FloatIsNaN,
        O::FloatAdd => Op::FloatAdd,
        O::FloatSub => Op::FloatSub,
        O::FloatMul => Op::FloatMul,
        O::FloatDiv => Op::FloatDiv,
        O::FloatNeg => Op::FloatNeg,
        O::FloatAbs => Op::FloatAbs,
        O::FloatSqrt => Op::FloatSqrt,
        O::FloatOfInt => Op::FloatOfInt,
        O::FloatOfFloat => Op::FloatOfFloat,
        O::FloatTruncate => Op::FloatTruncate,
        O::FloatCeiling => Op::FloatCeiling,
        O::FloatFloor => Op::FloatFloor,
        O::FloatRound => Op::FloatRound,
        O::Build => Op::Build,
        O::DelaySlot => Op::DelaySlot,
        O::Piece => Op::Piece,
        O::Subpiece => Op::Subpiece,
        O::Cast => Op::Cast,
        O::Label => Op::Label,
        O::CrossBuild => Op::CrossBuild,
        O::SegmentOp => Op::SegmentOp,
        O::CPoolRef => Op::CPoolRef,
        O::New => Op::New,
        O::Insert => Op::Insert,
        O::Extract => Op::Extract,
        O::PopCount => Op::PopCount,
        O::LZCount => Op::LZCount,
    }
}

fn push_const_tpl<'a>(tables: &mut Tables<'a>, tpl: &'a SleighConstTpl, value: ConstTpl) -> u16 {
    let idx = if let Some(idx) = tables.const_tpls.get_index_of(tpl) {
        idx
    } else {
        tables.const_tpls.insert_full(tpl, value).0
    };
    u16::try_from(idx).expect("const tpl id fits in u16")
}

fn push_construct_tpl<'a>(
    tables: &mut Tables<'a>,
    tpl: &'a SleighConstructTpl,
    value: blob::template::ConstructTpl,
) -> u16 {
    let idx = if let Some(idx) = tables.construct_tpls.get_index_of(tpl) {
        idx
    } else {
        tables.construct_tpls.insert_full(tpl, value).0
    };
    u16::try_from(idx).expect("construct tpl id fits in u16")
}

fn push_handle_tpl<'a>(tables: &mut Tables<'a>, tpl: &'a SleighHandleTpl, value: HandleTpl) -> u16 {
    let idx = if let Some(idx) = tables.handle_tpls.get_index_of(tpl) {
        idx
    } else {
        tables.handle_tpls.insert_full(tpl, value).0
    };
    u16::try_from(idx).expect("handle tpl id fits in u16")
}

fn push_op_tpl<'a>(
    tables: &mut Tables<'a>,
    tpl: &'a SleighOpTpl,
    value: blob::template::OpTpl,
) -> u16 {
    let idx = if let Some(idx) = tables.op_tpls.get_index_of(tpl) {
        idx
    } else {
        tables.op_tpls.insert_full(tpl, value).0
    };
    u16::try_from(idx).expect("op tpl id fits in u16")
}

fn push_varnode_tpl<'a>(
    tables: &mut Tables<'a>,
    tpl: &'a SleighVarnodeTpl,
    value: VarnodeTpl,
) -> u16 {
    let idx = if let Some(idx) = tables.varnode_tpls.get_index_of(tpl) {
        idx
    } else {
        tables.varnode_tpls.insert_full(tpl, value).0
    };
    u16::try_from(idx).expect("varnode tpl id fits in u16")
}
