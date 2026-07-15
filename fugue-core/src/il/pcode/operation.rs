use std::num::NonZeroU32;

use fugue_lifter::runtime::language::Language;
use fugue_lifter::{Op, Varnode};

use crate::il::common::{IlError, OperationId, PackedRange};
use crate::il::pcode::PCodeError;
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct LifterSpaceHandle(u8);

impl LifterSpaceHandle {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u8 {
        self.0
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct LocationId(NonZeroU32);

impl LocationId {
    pub fn try_from_index(index: usize) -> Result<Self, IlError> {
        let value = index
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .and_then(NonZeroU32::new)
            .ok_or(IlError::id_exhausted("PCode location"))?;

        Ok(Self(value))
    }

    pub const fn index(&self) -> usize {
        self.0.get() as usize - 1
    }

    pub const fn value(&self) -> u32 {
        self.0.get()
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct Location {
    offset: u64,
    width: u16,
    flags: u16,
    lifter_space: LifterSpaceHandle,
}

impl Location {
    pub const CONSTANT: u16 = 0x0001;
    pub const REGISTER: u16 = 0x0002;
    pub const UNIQUE: u16 = 0x0004;

    pub const fn new(lifter_space: LifterSpaceHandle, offset: u64, width: u16, flags: u16) -> Self {
        Self {
            offset,
            width,
            flags,
            lifter_space,
        }
    }

    pub fn from_varnode(varnode: &Varnode, language: &'static Language) -> Self {
        let lifter_space = LifterSpaceHandle::new(varnode.space());
        let flags = if varnode.space() == language.constant_space() {
            Self::CONSTANT
        } else if varnode.space() == language.register_space() {
            Self::REGISTER
        } else if varnode.space() == language.unique_space() {
            Self::UNIQUE
        } else {
            0
        };

        Self::new(lifter_space, varnode.offset(), varnode.size() as u16, flags)
    }

    pub const fn lifter_space(&self) -> LifterSpaceHandle {
        self.lifter_space
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn width(&self) -> u16 {
        self.width
    }

    pub const fn flags(&self) -> u16 {
        self.flags
    }

    pub const fn is_constant(&self) -> bool {
        self.flags & Self::CONSTANT != 0
    }

    pub const fn is_register(&self) -> bool {
        self.flags & Self::REGISTER != 0
    }

    pub const fn is_unique(&self) -> bool {
        self.flags & Self::UNIQUE != 0
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum Opcode {
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

impl TryFrom<Op> for Opcode {
    type Error = ();

    fn try_from(op: Op) -> Result<Self, Self::Error> {
        Ok(match op {
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
            Op::Arg => return Err(()),
            Op::UserOp(_, _) => Self::UserOp,
        })
    }
}

impl Opcode {
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

    pub const fn preserves_first_operand_width(&self) -> bool {
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
                | Self::FloatToFloat
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

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Operation {
    opcode: Opcode,
    operands: PackedRange,
    output: u32,
    immediate: u32,
    effect_space: u16,
}

impl Operation {
    const NO_LOCATION: u32 = 0;
    const NO_SPACE: u16 = u16::MAX;

    pub const fn new(
        opcode: Opcode,
        output: Option<LocationId>,
        operands: PackedRange,
        immediate: u32,
        effect_space: Option<AddressSpaceId>,
    ) -> Self {
        Self {
            opcode,
            operands,
            output: match output {
                Some(output) => output.value(),
                None => Self::NO_LOCATION,
            },
            immediate,
            effect_space: match effect_space {
                Some(space) => space.index() as u16,
                None => Self::NO_SPACE,
            },
        }
    }

    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    pub fn output(&self) -> Option<LocationId> {
        if self.output == Self::NO_LOCATION {
            None
        } else {
            NonZeroU32::new(self.output).map(LocationId)
        }
    }

    pub const fn operands(&self) -> PackedRange {
        self.operands
    }

    pub const fn immediate(&self) -> u32 {
        self.immediate
    }

    pub fn effect_space(&self) -> Option<AddressSpaceId> {
        if self.effect_space == Self::NO_SPACE {
            None
        } else {
            Some(AddressSpaceId::new(self.effect_space as usize))
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressAnnotationRole {
    DirectTarget,
    ComputedSpace,
    KnownTargets,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressAnnotationPayload<'a> {
    DirectTarget(Address),
    ComputedSpace(AddressSpaceId),
    KnownTargets(&'a [Address]),
}

impl AddressAnnotationPayload<'_> {
    pub const fn role(&self) -> AddressAnnotationRole {
        match self {
            Self::DirectTarget(_) => AddressAnnotationRole::DirectTarget,
            Self::ComputedSpace(_) => AddressAnnotationRole::ComputedSpace,
            Self::KnownTargets(_) => AddressAnnotationRole::KnownTargets,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressAnnotation<'a> {
    ordinal: OperationId,
    payload: AddressAnnotationPayload<'a>,
}

impl<'a> AddressAnnotation<'a> {
    pub const fn new(ordinal: OperationId, payload: AddressAnnotationPayload<'a>) -> Self {
        Self { ordinal, payload }
    }

    pub const fn ordinal(&self) -> OperationId {
        self.ordinal
    }

    pub const fn payload(&self) -> &AddressAnnotationPayload<'a> {
        &self.payload
    }
}

#[derive(Debug)]
pub struct PCodeAddressContext<'a> {
    source: Address,
    annotations: &'a [AddressAnnotation<'a>],
    cursor: usize,
}

impl<'a> PCodeAddressContext<'a> {
    pub const fn new(source: Address, annotations: &'a [AddressAnnotation<'a>]) -> Self {
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
        ordinal: OperationId,
        role: AddressAnnotationRole,
    ) -> Result<AddressAnnotationPayload<'a>, PCodeError> {
        let Some(annotation) = self.annotations.get(self.cursor) else {
            return Err(PCodeError::missing_annotation(ordinal.value(), role));
        };

        if annotation.ordinal() < ordinal {
            Err(PCodeError::out_of_order_annotation(
                annotation.ordinal().value(),
                annotation.payload().role(),
            ))
        } else if annotation.ordinal() == ordinal && annotation.payload().role() == role {
            if let Some(next) = self.annotations.get(self.cursor + 1)
                && next.ordinal() == ordinal
                && next.payload().role() == role
            {
                return Err(PCodeError::duplicate_annotation(ordinal.value(), role));
            }

            self.cursor += 1;
            Ok(annotation.payload().clone())
        } else if annotation.ordinal() == ordinal {
            Err(PCodeError::wrong_annotation_role(
                ordinal.value(),
                role,
                annotation.payload().role(),
            ))
        } else {
            Err(PCodeError::missing_annotation(ordinal.value(), role))
        }
    }

    pub fn finish(&self) -> Result<(), PCodeError> {
        if let Some(annotation) = self.annotations.get(self.cursor) {
            Err(PCodeError::unused_annotation(
                annotation.ordinal().value(),
                annotation.payload().role(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::ir::{Address, RawAddress};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn pcode_records_stay_compact() {
        assert_eq!(size_of::<LocationId>(), 4);
        assert_eq!(size_of::<Option<LocationId>>(), 4);
        assert!(size_of::<Location>() <= 16);
        assert!(size_of::<Operation>() <= 24);
    }

    #[test]
    fn address_context_consumes_annotations_in_order() {
        let ordinal = OperationId::try_from_index(0).unwrap();
        let target = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [AddressAnnotation::new(
            ordinal,
            AddressAnnotationPayload::DirectTarget(target),
        )];
        let mut context = PCodeAddressContext::new(target, &annotations);

        assert_eq!(
            context.take(ordinal, AddressAnnotationRole::DirectTarget),
            Ok(AddressAnnotationPayload::DirectTarget(target))
        );
        assert_eq!(context.finish(), Ok(()));
    }

    #[test]
    fn address_context_rejects_wrong_role() {
        let ordinal = OperationId::try_from_index(0).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [AddressAnnotation::new(
            ordinal,
            AddressAnnotationPayload::DirectTarget(source),
        )];
        let mut context = PCodeAddressContext::new(source, &annotations);

        assert!(matches!(
            context.take(ordinal, AddressAnnotationRole::ComputedSpace),
            Err(PCodeError::WrongAnnotationRole { .. })
        ));
    }

    #[test]
    fn address_context_rejects_duplicate_role() {
        let ordinal = OperationId::try_from_index(0).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [
            AddressAnnotation::new(ordinal, AddressAnnotationPayload::DirectTarget(source)),
            AddressAnnotation::new(ordinal, AddressAnnotationPayload::DirectTarget(source)),
        ];
        let mut context = PCodeAddressContext::new(source, &annotations);

        assert!(matches!(
            context.take(ordinal, AddressAnnotationRole::DirectTarget),
            Err(PCodeError::DuplicateAnnotation { .. })
        ));
    }

    #[test]
    fn address_context_rejects_out_of_order_annotation() {
        let first = OperationId::try_from_index(0).unwrap();
        let second = OperationId::try_from_index(1).unwrap();
        let source = Address::new(AddressSpaceId::new(1), RawAddress::from(0x401000u64));
        let annotations = [AddressAnnotation::new(
            first,
            AddressAnnotationPayload::DirectTarget(source),
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
