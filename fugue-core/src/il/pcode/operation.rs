use crate::il::common::{IlIndexRange, IlOpId, il_id};
use crate::il::pcode::PCodeError;
use crate::ir::{Address, Location};
use crate::lifter::{Language, Op, Varnode};
use crate::storage::segments::space::AddressSpaceId;
use crate::types::common::archived_bitflags;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct LifterSpaceHandle(u8);

impl LifterSpaceHandle {
    pub(crate) const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u8 {
        self.0
    }
}

il_id!(PCodeLocationId, "PCode location");

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct PCodeLocation {
    offset: u64,
    size: u16,
    properties: PCodeLocationProperties,
    lifter_space: LifterSpaceHandle,
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct PCodeLocationProperties: u16 {
        const CONSTANT = 0x0001;
        const REGISTER = 0x0002;
        const UNIQUE   = 0x0004;
    }
}

archived_bitflags!(
    PCodeLocationProperties,
    ArchivedPCodeLocationProperties,
    u16
);

impl PCodeLocation {
    pub(crate) const fn new(
        lifter_space: LifterSpaceHandle,
        offset: u64,
        size: u16,
        properties: PCodeLocationProperties,
    ) -> Self {
        Self {
            offset,
            size,
            properties,
            lifter_space,
        }
    }

    pub fn from_varnode(language: &'static Language, varnode: &Varnode) -> Self {
        let lifter_space = LifterSpaceHandle::new(varnode.space());
        let properties = if varnode.space() == language.constant_space() {
            PCodeLocationProperties::CONSTANT
        } else if varnode.space() == language.register_space() {
            PCodeLocationProperties::REGISTER
        } else if varnode.space() == language.unique_space() {
            PCodeLocationProperties::UNIQUE
        } else {
            PCodeLocationProperties::empty()
        };

        Self::new(
            lifter_space,
            varnode.offset(),
            varnode.size() as u16,
            properties,
        )
    }

    pub const fn lifter_space(&self) -> LifterSpaceHandle {
        self.lifter_space
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn size(&self) -> u16 {
        self.size
    }

    pub const fn bits(&self) -> u32 {
        self.size as u32 * 8
    }

    pub const fn properties(&self) -> PCodeLocationProperties {
        self.properties
    }

    pub const fn is_constant(&self) -> bool {
        self.properties.contains(PCodeLocationProperties::CONSTANT)
    }

    pub const fn is_register(&self) -> bool {
        self.properties.contains(PCodeLocationProperties::REGISTER)
    }

    pub const fn is_unique(&self) -> bool {
        self.properties.contains(PCodeLocationProperties::UNIQUE)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum PCodeOpcode {
    Copy = 0,
    Load = 1,
    Store = 2,
    IntAdd = 3,
    IntSub = 4,
    IntXor = 5,
    IntOr = 6,
    IntAnd = 7,
    IntMul = 8,
    IntDiv = 9,
    IntSignedDiv = 10,
    IntRem = 11,
    IntSignedRem = 12,
    IntLeftShift = 13,
    IntRightShift = 14,
    IntSignedRightShift = 15,
    IntEq = 16,
    IntNotEq = 17,
    IntLess = 18,
    IntSignedLess = 19,
    IntLessEq = 20,
    IntSignedLessEq = 21,
    IntCarry = 22,
    IntSignedCarry = 23,
    IntSignedBorrow = 24,
    IntNot = 25,
    IntNeg = 26,
    CountOnes = 27,
    CountLeadingZeros = 28,
    ZeroExt = 29,
    SignExt = 30,
    IntToFloat = 31,
    BoolAnd = 32,
    BoolOr = 33,
    BoolXor = 34,
    BoolNot = 35,
    FloatAdd = 36,
    FloatSub = 37,
    FloatMul = 38,
    FloatDiv = 39,
    FloatNeg = 40,
    FloatAbs = 41,
    FloatSqrt = 42,
    FloatCeiling = 43,
    FloatFloor = 44,
    FloatRound = 45,
    FloatIsNan = 46,
    FloatEq = 47,
    FloatNotEq = 48,
    FloatLess = 49,
    FloatLessEq = 50,
    FloatToInt = 51,
    FloatToFloat = 52,
    Branch = 53,
    CBranch = 54,
    IBranch = 55,
    Call = 56,
    ICall = 57,
    Return = 58,
    Subpiece = 59,
    UserOp = 60,
}

impl PCodeOpcode {
    pub(crate) fn from_op(op: Op) -> Option<Self> {
        Some(match op {
            Op::Copy => Self::Copy,
            Op::Load(_) => Self::Load,
            Op::Store(_) => Self::Store,
            Op::IntAdd => Self::IntAdd,
            Op::IntSub => Self::IntSub,
            Op::IntXor => Self::IntXor,
            Op::IntOr => Self::IntOr,
            Op::IntAnd => Self::IntAnd,
            Op::IntMul => Self::IntMul,
            Op::IntDiv => Self::IntDiv,
            Op::IntSignedDiv => Self::IntSignedDiv,
            Op::IntRem => Self::IntRem,
            Op::IntSignedRem => Self::IntSignedRem,
            Op::IntLeftShift => Self::IntLeftShift,
            Op::IntRightShift => Self::IntRightShift,
            Op::IntSignedRightShift => Self::IntSignedRightShift,
            Op::IntEq => Self::IntEq,
            Op::IntNotEq => Self::IntNotEq,
            Op::IntLess => Self::IntLess,
            Op::IntSignedLess => Self::IntSignedLess,
            Op::IntLessEq => Self::IntLessEq,
            Op::IntSignedLessEq => Self::IntSignedLessEq,
            Op::IntCarry => Self::IntCarry,
            Op::IntSignedCarry => Self::IntSignedCarry,
            Op::IntSignedBorrow => Self::IntSignedBorrow,
            Op::IntNot => Self::IntNot,
            Op::IntNeg => Self::IntNeg,
            Op::CountOnes => Self::CountOnes,
            Op::CountLeadingZeros => Self::CountLeadingZeros,
            Op::ZeroExt => Self::ZeroExt,
            Op::SignExt => Self::SignExt,
            Op::IntToFloat => Self::IntToFloat,
            Op::BoolAnd => Self::BoolAnd,
            Op::BoolOr => Self::BoolOr,
            Op::BoolXor => Self::BoolXor,
            Op::BoolNot => Self::BoolNot,
            Op::FloatAdd => Self::FloatAdd,
            Op::FloatSub => Self::FloatSub,
            Op::FloatMul => Self::FloatMul,
            Op::FloatDiv => Self::FloatDiv,
            Op::FloatNeg => Self::FloatNeg,
            Op::FloatAbs => Self::FloatAbs,
            Op::FloatSqrt => Self::FloatSqrt,
            Op::FloatCeiling => Self::FloatCeiling,
            Op::FloatFloor => Self::FloatFloor,
            Op::FloatRound => Self::FloatRound,
            Op::FloatIsNaN => Self::FloatIsNan,
            Op::FloatEq => Self::FloatEq,
            Op::FloatNotEq => Self::FloatNotEq,
            Op::FloatLess => Self::FloatLess,
            Op::FloatLessEq => Self::FloatLessEq,
            Op::FloatToInt => Self::FloatToInt,
            Op::FloatToFloat => Self::FloatToFloat,
            Op::Branch => Self::Branch,
            Op::CBranch => Self::CBranch,
            Op::IBranch => Self::IBranch,
            Op::Call => Self::Call,
            Op::ICall => Self::ICall,
            Op::Return => Self::Return,
            Op::Subpiece => Self::Subpiece,
            Op::Arg => return None,
            Op::UserOp(_, _) => Self::UserOp,
        })
    }

    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Load => "load",
            Self::Store => "store",
            Self::IntAdd => "int_add",
            Self::IntSub => "int_sub",
            Self::IntXor => "int_xor",
            Self::IntOr => "int_or",
            Self::IntAnd => "int_and",
            Self::IntMul => "int_mul",
            Self::IntDiv => "int_div",
            Self::IntSignedDiv => "int_signed_div",
            Self::IntRem => "int_rem",
            Self::IntSignedRem => "int_signed_rem",
            Self::IntLeftShift => "int_left_shift",
            Self::IntRightShift => "int_right_shift",
            Self::IntSignedRightShift => "int_signed_right_shift",
            Self::IntEq => "int_eq",
            Self::IntNotEq => "int_not_eq",
            Self::IntLess => "int_less",
            Self::IntSignedLess => "int_signed_less",
            Self::IntLessEq => "int_less_eq",
            Self::IntSignedLessEq => "int_signed_less_eq",
            Self::IntCarry => "int_carry",
            Self::IntSignedCarry => "int_signed_carry",
            Self::IntSignedBorrow => "int_signed_borrow",
            Self::IntNot => "int_not",
            Self::IntNeg => "int_neg",
            Self::CountOnes => "count_ones",
            Self::CountLeadingZeros => "count_leading_zeros",
            Self::ZeroExt => "zero_ext",
            Self::SignExt => "sign_ext",
            Self::IntToFloat => "int_to_float",
            Self::BoolAnd => "bool_and",
            Self::BoolOr => "bool_or",
            Self::BoolXor => "bool_xor",
            Self::BoolNot => "bool_not",
            Self::FloatAdd => "float_add",
            Self::FloatSub => "float_sub",
            Self::FloatMul => "float_mul",
            Self::FloatDiv => "float_div",
            Self::FloatNeg => "float_neg",
            Self::FloatAbs => "float_abs",
            Self::FloatSqrt => "float_sqrt",
            Self::FloatCeiling => "float_ceiling",
            Self::FloatFloor => "float_floor",
            Self::FloatRound => "float_round",
            Self::FloatIsNan => "float_is_nan",
            Self::FloatEq => "float_eq",
            Self::FloatNotEq => "float_not_eq",
            Self::FloatLess => "float_less",
            Self::FloatLessEq => "float_less_eq",
            Self::FloatToInt => "float_to_int",
            Self::FloatToFloat => "float_to_float",
            Self::Branch => "branch",
            Self::CBranch => "cbranch",
            Self::IBranch => "ibranch",
            Self::Call => "call",
            Self::ICall => "icall",
            Self::Return => "return",
            Self::Subpiece => "subpiece",
            Self::UserOp => "user_op",
        }
    }

    pub const fn requires_effect_space(&self) -> bool {
        matches!(
            self,
            Self::Load | Self::Store | Self::IBranch | Self::ICall | Self::Return
        )
    }

    pub const fn requires_target(&self) -> bool {
        matches!(self, Self::Branch | Self::CBranch | Self::Call)
    }

    pub const fn fixed_operand_count(&self) -> Option<usize> {
        match self {
            Self::Copy
            | Self::Load
            | Self::IntNot
            | Self::IntNeg
            | Self::CountOnes
            | Self::CountLeadingZeros
            | Self::ZeroExt
            | Self::SignExt
            | Self::IntToFloat
            | Self::BoolNot
            | Self::FloatNeg
            | Self::FloatAbs
            | Self::FloatSqrt
            | Self::FloatCeiling
            | Self::FloatFloor
            | Self::FloatRound
            | Self::FloatIsNan
            | Self::FloatToInt
            | Self::FloatToFloat
            | Self::Branch
            | Self::IBranch
            | Self::Call
            | Self::ICall
            | Self::Return => Some(1),
            Self::Store
            | Self::IntAdd
            | Self::IntSub
            | Self::IntXor
            | Self::IntOr
            | Self::IntAnd
            | Self::IntMul
            | Self::IntDiv
            | Self::IntSignedDiv
            | Self::IntRem
            | Self::IntSignedRem
            | Self::IntLeftShift
            | Self::IntRightShift
            | Self::IntSignedRightShift
            | Self::IntEq
            | Self::IntNotEq
            | Self::IntLess
            | Self::IntSignedLess
            | Self::IntLessEq
            | Self::IntSignedLessEq
            | Self::IntCarry
            | Self::IntSignedCarry
            | Self::IntSignedBorrow
            | Self::BoolAnd
            | Self::BoolOr
            | Self::BoolXor
            | Self::FloatAdd
            | Self::FloatSub
            | Self::FloatMul
            | Self::FloatDiv
            | Self::FloatEq
            | Self::FloatNotEq
            | Self::FloatLess
            | Self::FloatLessEq
            | Self::CBranch
            | Self::Subpiece => Some(2),
            Self::UserOp => None,
        }
    }

    pub const fn requires_output(&self) -> bool {
        !matches!(
            self,
            Self::Store
                | Self::Branch
                | Self::CBranch
                | Self::IBranch
                | Self::Call
                | Self::ICall
                | Self::Return
                | Self::UserOp
        )
    }

    pub const fn forbids_output(&self) -> bool {
        matches!(
            self,
            Self::Store
                | Self::Branch
                | Self::CBranch
                | Self::IBranch
                | Self::Call
                | Self::ICall
                | Self::Return
        )
    }

    pub const fn preserves_first_operand_size(&self) -> bool {
        matches!(
            self,
            Self::Copy
                | Self::IntAdd
                | Self::IntSub
                | Self::IntXor
                | Self::IntOr
                | Self::IntAnd
                | Self::IntMul
                | Self::IntDiv
                | Self::IntSignedDiv
                | Self::IntRem
                | Self::IntSignedRem
                | Self::IntLeftShift
                | Self::IntRightShift
                | Self::IntSignedRightShift
                | Self::IntNot
                | Self::IntNeg
                | Self::BoolAnd
                | Self::BoolOr
                | Self::BoolXor
                | Self::BoolNot
                | Self::FloatAdd
                | Self::FloatSub
                | Self::FloatMul
                | Self::FloatDiv
                | Self::FloatNeg
                | Self::FloatAbs
                | Self::FloatSqrt
                | Self::FloatCeiling
                | Self::FloatFloor
                | Self::FloatRound
        )
    }

    pub const fn compares_operands(&self) -> bool {
        matches!(
            self,
            Self::IntEq
                | Self::IntNotEq
                | Self::IntLess
                | Self::IntSignedLess
                | Self::IntLessEq
                | Self::IntSignedLessEq
                | Self::IntCarry
                | Self::IntSignedCarry
                | Self::IntSignedBorrow
                | Self::FloatEq
                | Self::FloatNotEq
                | Self::FloatLess
                | Self::FloatLessEq
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PCodeOp {
    opcode: PCodeOpcode,
    operands: IlIndexRange,
    output: Option<PCodeLocationId>,
    immediate: u32,
    effect_space: Option<AddressSpaceId>,
}

impl PCodeOp {
    pub(crate) const fn new(
        opcode: PCodeOpcode,
        output: Option<PCodeLocationId>,
        operands: IlIndexRange,
        immediate: u32,
        effect_space: Option<AddressSpaceId>,
    ) -> Self {
        Self {
            opcode,
            operands,
            output,
            immediate,
            effect_space,
        }
    }

    pub const fn opcode(&self) -> PCodeOpcode {
        self.opcode
    }

    pub const fn output(&self) -> Option<PCodeLocationId> {
        self.output
    }

    pub const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub const fn immediate(&self) -> u32 {
        self.immediate
    }

    pub const fn effect_space(&self) -> Option<AddressSpaceId> {
        self.effect_space
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressAnnotationRole {
    ComputedSpace,
    DirectTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressAnnotationValue {
    ComputedSpace(AddressSpaceId),
    DirectTarget(Location),
}

impl AddressAnnotationValue {
    pub const fn role(&self) -> AddressAnnotationRole {
        match self {
            Self::DirectTarget(_) => AddressAnnotationRole::DirectTarget,
            Self::ComputedSpace(_) => AddressAnnotationRole::ComputedSpace,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressAnnotation {
    ordinal: IlOpId,
    value: AddressAnnotationValue,
}

impl AddressAnnotation {
    pub(crate) const fn new(ordinal: IlOpId, value: AddressAnnotationValue) -> Self {
        Self { ordinal, value }
    }

    pub const fn ordinal(&self) -> IlOpId {
        self.ordinal
    }

    pub const fn value(&self) -> &AddressAnnotationValue {
        &self.value
    }
}

#[derive(Debug)]
pub struct PCodeAddressContext<'a> {
    source: Address,
    annotations: &'a [AddressAnnotation],
    cursor: usize,
}

impl<'a> PCodeAddressContext<'a> {
    pub(crate) const fn new(source: Address, annotations: &'a [AddressAnnotation]) -> Self {
        Self {
            source,
            annotations,
            cursor: 0,
        }
    }

    pub const fn source(&self) -> Address {
        self.source
    }

    pub fn take(
        &mut self,
        ordinal: IlOpId,
        role: AddressAnnotationRole,
    ) -> Result<AddressAnnotationValue, PCodeError> {
        let Some(annotation) = self.annotations.get(self.cursor) else {
            return Err(PCodeError::missing_annotation(ordinal.value(), role));
        };

        if annotation.ordinal() < ordinal {
            Err(PCodeError::out_of_order_annotation(
                annotation.ordinal().value(),
                annotation.value().role(),
            ))
        } else if annotation.ordinal() == ordinal && annotation.value().role() == role {
            if let Some(next) = self.annotations.get(self.cursor + 1)
                && next.ordinal() == ordinal
                && next.value().role() == role
            {
                return Err(PCodeError::duplicate_annotation(ordinal.value(), role));
            }

            self.cursor += 1;
            Ok(annotation.value().clone())
        } else if annotation.ordinal() == ordinal {
            Err(PCodeError::wrong_annotation_role(
                ordinal.value(),
                role,
                annotation.value().role(),
            ))
        } else {
            Err(PCodeError::missing_annotation(ordinal.value(), role))
        }
    }

    pub fn ensure_consumed(&self) -> Result<(), PCodeError> {
        if let Some(annotation) = self.annotations.get(self.cursor) {
            Err(PCodeError::unused_annotation(
                annotation.ordinal().value(),
                annotation.value().role(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;
    use crate::ir::{Address, RawAddress};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn pcode_records_stay_compact() {
        assert_eq!(size_of::<PCodeLocationId>(), 4);
        assert_eq!(size_of::<Option<PCodeLocationId>>(), 4);
        assert!(size_of::<PCodeLocation>() <= 16);
        assert!(size_of::<PCodeOp>() <= 24);
    }

    #[test]
    fn address_context_consumes_annotations_in_order() {
        let ordinal = IlOpId::try_from_index(0).unwrap();
        let target = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [AddressAnnotation::new(
            ordinal,
            AddressAnnotationValue::DirectTarget(target.into()),
        )];
        let mut context = PCodeAddressContext::new(target, &annotations);

        assert!(matches!(
            context.take(ordinal, AddressAnnotationRole::DirectTarget),
            Ok(AddressAnnotationValue::DirectTarget(taken)) if taken == target.into()
        ));
        assert!(context.ensure_consumed().is_ok());
    }

    #[test]
    fn address_context_rejects_wrong_role() {
        let ordinal = IlOpId::try_from_index(0).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [AddressAnnotation::new(
            ordinal,
            AddressAnnotationValue::DirectTarget(source.into()),
        )];
        let mut context = PCodeAddressContext::new(source, &annotations);

        assert!(matches!(
            context.take(ordinal, AddressAnnotationRole::ComputedSpace),
            Err(PCodeError::WrongAnnotationRole { .. })
        ));
    }

    #[test]
    fn address_context_rejects_duplicate_role() {
        let ordinal = IlOpId::try_from_index(0).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [
            AddressAnnotation::new(ordinal, AddressAnnotationValue::DirectTarget(source.into())),
            AddressAnnotation::new(ordinal, AddressAnnotationValue::DirectTarget(source.into())),
        ];
        let mut context = PCodeAddressContext::new(source, &annotations);

        assert!(matches!(
            context.take(ordinal, AddressAnnotationRole::DirectTarget),
            Err(PCodeError::DuplicateAnnotation { .. })
        ));
    }

    #[test]
    fn address_context_rejects_out_of_order_annotation() {
        let first = IlOpId::try_from_index(0).unwrap();
        let second = IlOpId::try_from_index(1).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [AddressAnnotation::new(
            first,
            AddressAnnotationValue::DirectTarget(source.into()),
        )];
        let mut context = PCodeAddressContext::new(source, &annotations);

        assert!(matches!(
            context.take(second, AddressAnnotationRole::DirectTarget),
            Err(PCodeError::OutOfOrderAnnotation { .. })
        ));
    }

    #[test]
    fn lifter_space_handle_has_no_address_space_conversion() {
        let handle = LifterSpaceHandle::new(7);

        assert_eq!(handle.value(), 7);
        assert_eq!(std::mem::size_of::<LifterSpaceHandle>(), 1);
    }
}
