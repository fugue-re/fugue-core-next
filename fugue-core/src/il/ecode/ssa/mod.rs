pub mod builder;
pub mod def_use;
pub mod format;
pub(crate) mod intervals;
pub mod liveness;
pub mod memory;
pub mod transform;
mod verify;

pub(crate) use builder::ECodeSsaBuilder;
pub use builder::{ECODE_SSA_SCHEMA_VERSION, ECodeSsaIr};
pub use def_use::{ECodeSsaUse, ECodeSsaUses};
pub use format::{
    ECodeSsaIrDisplay, ECodeSsaOpDisplay, ECodeSsaOpcodeDisplay, ECodeSsaValueDisplay,
};
use fugue_bv::BitVec;
pub(crate) use intervals::StridedIntervals;
pub use liveness::ECodeSsaLiveness;
pub use memory::ECodeSsaMemoryDomain;
pub use transform::ECodeToSsa;
pub(crate) use verify::verify;

use crate::il::common::{IlBlockId, IlIndexRange, IlOpId, IlValueId};
use crate::il::ecode::{ECodeExprOpcode, ECodeStmtOpcode};
use crate::ir::Address;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeSsaValue {
    width: u32,
    definition_kind: ECodeSsaValueKind,
    definition_index: u32,
}

impl ECodeSsaValue {
    pub(crate) const fn new(
        width: u32,
        definition_kind: ECodeSsaValueKind,
        definition_index: u32,
    ) -> Self {
        Self {
            width,
            definition_kind,
            definition_index,
        }
    }

    pub const fn operation_result(width: u32, operation: IlOpId) -> Self {
        Self::new(
            width,
            ECodeSsaValueKind::Operation,
            operation.index() as u32,
        )
    }

    pub const fn block_argument(width: u32, argument: u32) -> Self {
        Self::new(width, ECodeSsaValueKind::BlockArgument, argument)
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn definition_kind(&self) -> ECodeSsaValueKind {
        self.definition_kind
    }

    pub const fn definition_index(&self) -> u32 {
        self.definition_index
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum ECodeSsaValueKind {
    Operation = 0,
    BlockArgument = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct ECodeSsaBlockArg {
    block: IlBlockId,
    value: IlValueId,
    width: u32,
}

impl ECodeSsaBlockArg {
    pub(crate) const fn new(block: IlBlockId, value: IlValueId, width: u32) -> Self {
        Self {
            block,
            value,
            width,
        }
    }

    pub const fn block(&self) -> IlBlockId {
        self.block
    }

    pub const fn value(&self) -> IlValueId {
        self.value
    }

    pub const fn width(&self) -> u32 {
        self.width
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(u16)]
pub enum ECodeSsaOpcode {
    Constant = 0,
    Address = 1,
    Undefined = 2,
    Load = 3,
    Copy = 4,
    Add = 5,
    Sub = 6,
    Mul = 7,
    UnsignedDiv = 8,
    SignedDiv = 9,
    UnsignedRem = 10,
    SignedRem = 11,
    Negate = 12,
    LeftShift = 13,
    LogicalRightShift = 14,
    ArithmeticRightShift = 15,
    And = 16,
    Or = 17,
    Xor = 18,
    Not = 19,
    IntEqual = 20,
    IntNotEqual = 21,
    IntLess = 22,
    IntSignedLess = 23,
    IntLessEqual = 24,
    IntSignedLessEqual = 25,
    Carry = 26,
    SignedCarry = 27,
    SignedBorrow = 28,
    CountOnes = 29,
    CountLeadingZeros = 30,
    ZeroExtend = 31,
    SignExtend = 32,
    Truncate = 33,
    Extract = 34,
    Insert = 35,
    FloatAdd = 36,
    FloatSub = 37,
    FloatMul = 38,
    FloatDiv = 39,
    FloatNegate = 40,
    FloatAbs = 41,
    FloatSqrt = 42,
    FloatCeiling = 43,
    FloatFloor = 44,
    FloatRound = 45,
    FloatIsNan = 46,
    FloatEqual = 47,
    FloatNotEqual = 48,
    FloatLess = 49,
    FloatLessEqual = 50,
    FloatToInt = 51,
    FloatToFloat = 52,
    IntToFloat = 53,
    IntrinsicResult = 54,
    Intrinsic = 55,
    Store = 56,
    Branch = 57,
    ConditionalBranch = 58,
    BranchIndirect = 59,
    Call = 60,
    CallIndirect = 61,
    Return = 62,
    Trap = 63,
    BoolAnd = 64,
    BoolOr = 65,
    BoolXor = 66,
    BoolNot = 67,
}

impl ECodeSsaOpcode {
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Constant => "const",
            Self::Address => "addr",
            Self::Undefined => "undef",
            Self::Load => "load",
            Self::Copy => "copy",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::UnsignedDiv => "udiv",
            Self::SignedDiv => "sdiv",
            Self::UnsignedRem => "urem",
            Self::SignedRem => "srem",
            Self::Negate => "neg",
            Self::LeftShift => "shl",
            Self::LogicalRightShift => "lshr",
            Self::ArithmeticRightShift => "ashr",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
            Self::BoolAnd => "booland",
            Self::BoolOr => "boolor",
            Self::BoolXor => "boolxor",
            Self::BoolNot => "boolnot",
            Self::IntEqual => "eq",
            Self::IntNotEqual => "ne",
            Self::IntLess => "lt",
            Self::IntSignedLess => "slt",
            Self::IntLessEqual => "le",
            Self::IntSignedLessEqual => "sle",
            Self::Carry => "carry",
            Self::SignedCarry => "scarry",
            Self::SignedBorrow => "sborrow",
            Self::CountOnes => "popcount",
            Self::CountLeadingZeros => "clz",
            Self::ZeroExtend => "zext",
            Self::SignExtend => "sext",
            Self::Truncate => "trunc",
            Self::Extract => "extract",
            Self::Insert => "insert",
            Self::FloatAdd => "fadd",
            Self::FloatSub => "fsub",
            Self::FloatMul => "fmul",
            Self::FloatDiv => "fdiv",
            Self::FloatNegate => "fneg",
            Self::FloatAbs => "fabs",
            Self::FloatSqrt => "fsqrt",
            Self::FloatCeiling => "fceil",
            Self::FloatFloor => "ffloor",
            Self::FloatRound => "fround",
            Self::FloatIsNan => "fisnan",
            Self::FloatEqual => "feq",
            Self::FloatNotEqual => "fne",
            Self::FloatLess => "flt",
            Self::FloatLessEqual => "fle",
            Self::FloatToInt => "f2i",
            Self::FloatToFloat => "f2f",
            Self::IntToFloat => "i2f",
            Self::IntrinsicResult => "intrinsic_result",
            Self::Intrinsic => "intrinsic",
            Self::Store => "store",
            Self::Branch => "br",
            Self::ConditionalBranch => "cbr",
            Self::BranchIndirect => "ibr",
            Self::Call => "call",
            Self::CallIndirect => "icall",
            Self::Return => "ret",
            Self::Trap => "trap",
        }
    }

    pub const fn from_expression(opcode: ECodeExprOpcode) -> Option<Self> {
        match opcode {
            ECodeExprOpcode::ReadRegister | ECodeExprOpcode::ReadFlag => None,
            ECodeExprOpcode::Constant => Some(Self::Constant),
            ECodeExprOpcode::Address => Some(Self::Address),
            ECodeExprOpcode::Undefined => Some(Self::Undefined),
            ECodeExprOpcode::Load => Some(Self::Load),
            ECodeExprOpcode::Copy => Some(Self::Copy),
            ECodeExprOpcode::Add => Some(Self::Add),
            ECodeExprOpcode::Sub => Some(Self::Sub),
            ECodeExprOpcode::Mul => Some(Self::Mul),
            ECodeExprOpcode::UnsignedDiv => Some(Self::UnsignedDiv),
            ECodeExprOpcode::SignedDiv => Some(Self::SignedDiv),
            ECodeExprOpcode::UnsignedRem => Some(Self::UnsignedRem),
            ECodeExprOpcode::SignedRem => Some(Self::SignedRem),
            ECodeExprOpcode::Negate => Some(Self::Negate),
            ECodeExprOpcode::LeftShift => Some(Self::LeftShift),
            ECodeExprOpcode::LogicalRightShift => Some(Self::LogicalRightShift),
            ECodeExprOpcode::ArithmeticRightShift => Some(Self::ArithmeticRightShift),
            ECodeExprOpcode::And => Some(Self::And),
            ECodeExprOpcode::Or => Some(Self::Or),
            ECodeExprOpcode::Xor => Some(Self::Xor),
            ECodeExprOpcode::Not => Some(Self::Not),
            ECodeExprOpcode::BoolAnd => Some(Self::BoolAnd),
            ECodeExprOpcode::BoolOr => Some(Self::BoolOr),
            ECodeExprOpcode::BoolXor => Some(Self::BoolXor),
            ECodeExprOpcode::BoolNot => Some(Self::BoolNot),
            ECodeExprOpcode::IntEqual => Some(Self::IntEqual),
            ECodeExprOpcode::IntNotEqual => Some(Self::IntNotEqual),
            ECodeExprOpcode::IntLess => Some(Self::IntLess),
            ECodeExprOpcode::IntSignedLess => Some(Self::IntSignedLess),
            ECodeExprOpcode::IntLessEqual => Some(Self::IntLessEqual),
            ECodeExprOpcode::IntSignedLessEqual => Some(Self::IntSignedLessEqual),
            ECodeExprOpcode::Carry => Some(Self::Carry),
            ECodeExprOpcode::SignedCarry => Some(Self::SignedCarry),
            ECodeExprOpcode::SignedBorrow => Some(Self::SignedBorrow),
            ECodeExprOpcode::CountOnes => Some(Self::CountOnes),
            ECodeExprOpcode::CountLeadingZeros => Some(Self::CountLeadingZeros),
            ECodeExprOpcode::ZeroExtend => Some(Self::ZeroExtend),
            ECodeExprOpcode::SignExtend => Some(Self::SignExtend),
            ECodeExprOpcode::Truncate => Some(Self::Truncate),
            ECodeExprOpcode::Extract => Some(Self::Extract),
            ECodeExprOpcode::Insert => Some(Self::Insert),
            ECodeExprOpcode::FloatAdd => Some(Self::FloatAdd),
            ECodeExprOpcode::FloatSub => Some(Self::FloatSub),
            ECodeExprOpcode::FloatMul => Some(Self::FloatMul),
            ECodeExprOpcode::FloatDiv => Some(Self::FloatDiv),
            ECodeExprOpcode::FloatNegate => Some(Self::FloatNegate),
            ECodeExprOpcode::FloatAbs => Some(Self::FloatAbs),
            ECodeExprOpcode::FloatSqrt => Some(Self::FloatSqrt),
            ECodeExprOpcode::FloatCeiling => Some(Self::FloatCeiling),
            ECodeExprOpcode::FloatFloor => Some(Self::FloatFloor),
            ECodeExprOpcode::FloatRound => Some(Self::FloatRound),
            ECodeExprOpcode::FloatIsNan => Some(Self::FloatIsNan),
            ECodeExprOpcode::FloatEqual => Some(Self::FloatEqual),
            ECodeExprOpcode::FloatNotEqual => Some(Self::FloatNotEqual),
            ECodeExprOpcode::FloatLess => Some(Self::FloatLess),
            ECodeExprOpcode::FloatLessEqual => Some(Self::FloatLessEqual),
            ECodeExprOpcode::FloatToInt => Some(Self::FloatToInt),
            ECodeExprOpcode::FloatToFloat => Some(Self::FloatToFloat),
            ECodeExprOpcode::IntToFloat => Some(Self::IntToFloat),
            ECodeExprOpcode::IntrinsicResult => Some(Self::IntrinsicResult),
        }
    }

    pub const fn from_statement(opcode: ECodeStmtOpcode) -> Option<Self> {
        match opcode {
            ECodeStmtOpcode::WriteRegister | ECodeStmtOpcode::WriteFlag => None,
            ECodeStmtOpcode::Store => Some(Self::Store),
            ECodeStmtOpcode::Intrinsic => Some(Self::Intrinsic),
            ECodeStmtOpcode::Branch => Some(Self::Branch),
            ECodeStmtOpcode::BranchIndirect => Some(Self::BranchIndirect),
            ECodeStmtOpcode::ConditionalBranch => Some(Self::ConditionalBranch),
            ECodeStmtOpcode::Call => Some(Self::Call),
            ECodeStmtOpcode::CallIndirect => Some(Self::CallIndirect),
            ECodeStmtOpcode::Return => Some(Self::Return),
            ECodeStmtOpcode::Trap => Some(Self::Trap),
        }
    }

    pub const fn requires_memory_domain(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }

    pub const fn is_dce_root(self) -> bool {
        matches!(
            self,
            Self::Store
                | Self::Intrinsic
                | Self::IntrinsicResult
                | Self::Branch
                | Self::ConditionalBranch
                | Self::BranchIndirect
                | Self::Call
                | Self::CallIndirect
                | Self::Return
                | Self::Trap
        )
    }

    pub const fn has_uniform_operand_width(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Sub
                | Self::Mul
                | Self::UnsignedDiv
                | Self::SignedDiv
                | Self::UnsignedRem
                | Self::SignedRem
                | Self::Negate
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Not
        )
    }

    pub fn evaluate(self, width: u32, operands: &[BitVec]) -> Option<BitVec> {
        let arg = |index: usize| operands.get(index).cloned();
        match self {
            Self::Copy => Some(arg(0)?.cast(width)),
            Self::Not => Some(!arg(0)?.cast(width)),
            Self::Negate => Some(-arg(0)?.cast(width)),
            Self::Add => Some(arg(0)?.cast(width) + arg(1)?.cast(width)),
            Self::Sub => Some(arg(0)?.cast(width) - arg(1)?.cast(width)),
            Self::Mul => Some(arg(0)?.cast(width) * arg(1)?.cast(width)),
            Self::And => Some(arg(0)?.cast(width) & arg(1)?.cast(width)),
            Self::Or => Some(arg(0)?.cast(width) | arg(1)?.cast(width)),
            Self::Xor => Some(arg(0)?.cast(width) ^ arg(1)?.cast(width)),
            Self::LeftShift => Some(arg(0)?.cast(width) << arg(1)?.cast(width)),
            Self::LogicalRightShift => Some(arg(0)?.cast(width).unsigned() >> arg(1)?.cast(width)),
            Self::ArithmeticRightShift => Some(arg(0)?.cast(width).signed() >> arg(1)?.cast(width)),
            Self::ZeroExtend => Some(arg(0)?.unsigned_cast(width)),
            Self::SignExtend => Some(arg(0)?.signed_cast(width)),
            Self::Truncate => Some(arg(0)?.cast(width)),
            Self::BoolAnd => Some(arg(0)?.cast(width) & arg(1)?.cast(width)),
            Self::BoolOr => Some(arg(0)?.cast(width) | arg(1)?.cast(width)),
            Self::BoolXor => Some(arg(0)?.cast(width) ^ arg(1)?.cast(width)),
            Self::BoolNot => Some(!arg(0)?.cast(width)),
            Self::CountOnes => Some(BitVec::from_u64(u64::from(arg(0)?.count_ones()), width)),
            Self::CountLeadingZeros => {
                Some(BitVec::from_u64(u64::from(arg(0)?.leading_zeros()), width))
            }
            Self::UnsignedDiv => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.unsigned() / b.unsigned())
            }
            Self::SignedDiv => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.signed() / b.signed())
            }
            Self::UnsignedRem => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.unsigned() % b.unsigned())
            }
            Self::SignedRem => {
                let (a, b) = (arg(0)?.cast(width), arg(1)?.cast(width));
                (!b.is_zero()).then(|| a.signed() % b.signed())
            }
            Self::IntEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a == b) as u64, width))
            }
            Self::IntNotEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a != b) as u64, width))
            }
            Self::IntLess => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    (a.unsigned() < b.unsigned()) as u64,
                    width,
                ))
            }
            Self::IntLessEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    (a.unsigned() <= b.unsigned()) as u64,
                    width,
                ))
            }
            Self::IntSignedLess => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a.signed() < b.signed()) as u64, width))
            }
            Self::IntSignedLessEqual => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64((a.signed() <= b.signed()) as u64, width))
            }
            Self::Carry => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(
                    a.unsigned().carry(&b.unsigned()) as u64,
                    width,
                ))
            }
            Self::SignedCarry => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(a.signed_carry(&b) as u64, width))
            }
            Self::SignedBorrow => {
                let (a, b) = (arg(0)?, arg(1)?);
                if a.bits() != b.bits() {
                    return None;
                }
                Some(BitVec::from_u64(a.signed_borrow(&b) as u64, width))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ECodeSsaOp {
    opcode: ECodeSsaOpcode,
    results: IlIndexRange,
    operands: IlIndexRange,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<AddressSpaceId>,
}

impl ECodeSsaOp {
    pub(crate) const fn new(
        opcode: ECodeSsaOpcode,
        results: IlIndexRange,
        operands: IlIndexRange,
        width: u32,
    ) -> Self {
        Self {
            opcode,
            results,
            operands,
            width,
            immediate: 0,
            address: None,
            address_space: None,
        }
    }

    pub const fn with_immediate(mut self, immediate: u64) -> Self {
        self.immediate = immediate;
        self
    }

    pub const fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }

    pub const fn with_address_space(mut self, address_space: AddressSpaceId) -> Self {
        self.address_space = Some(address_space);
        self
    }

    pub const fn opcode(&self) -> ECodeSsaOpcode {
        self.opcode
    }

    pub const fn results(&self) -> IlIndexRange {
        self.results
    }

    pub const fn operands(&self) -> IlIndexRange {
        self.operands
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn immediate(&self) -> u64 {
        self.immediate
    }

    pub const fn address(&self) -> Option<Address> {
        self.address
    }

    pub const fn address_space(&self) -> Option<AddressSpaceId> {
        self.address_space
    }

    pub(crate) fn constant(&self, constants: &[u8]) -> Option<BitVec> {
        if !matches!(self.opcode, ECodeSsaOpcode::Constant) {
            return None;
        }
        if self.width <= 64 {
            return Some(BitVec::from_u64(self.immediate, self.width));
        }
        let bytes = self.width.div_ceil(8) as usize;
        let start = self.immediate as usize;
        let slice = constants.get(start..start + bytes)?;
        Some(BitVec::from_le_bytes(slice).cast(self.width))
    }

    pub(crate) fn replace_with_constant(&mut self, immediate: u64) {
        self.opcode = ECodeSsaOpcode::Constant;
        self.operands = IlIndexRange::EMPTY;
        self.immediate = immediate;
        self.address = None;
        self.address_space = None;
    }

    pub(crate) fn make_undefined(&mut self) {
        self.opcode = ECodeSsaOpcode::Undefined;
        self.operands = IlIndexRange::EMPTY;
        self.immediate = 0;
        self.address = None;
        self.address_space = None;
    }

    pub(crate) fn set_results(&mut self, results: IlIndexRange) {
        self.results = results;
    }

    pub(crate) fn set_operands(&mut self, operands: IlIndexRange) {
        self.operands = operands;
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn ssa_records_stay_compact() {
        assert!(size_of::<ECodeSsaValue>() <= 12);
        assert!(size_of::<ECodeSsaBlockArg>() <= 12);
        assert!(size_of::<ECodeSsaOp>() <= 64);
    }

    #[test]
    fn evaluate_folds_comparisons_at_operand_width() {
        let seven = BitVec::from_u64(7, 32);
        let nine = BitVec::from_u64(9, 32);
        let one = BitVec::from_u64(1, 1);
        let zero = BitVec::from_u64(0, 1);

        assert_eq!(
            ECodeSsaOpcode::IntLess.evaluate(1, &[seven.clone(), nine.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::IntLessEqual.evaluate(1, &[seven.clone(), seven.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::IntEqual.evaluate(1, &[seven.clone(), nine.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::IntNotEqual.evaluate(1, &[seven.clone(), nine.clone()]),
            Some(one.clone())
        );

        let minus_one = BitVec::from_u64(u64::from(u32::MAX), 32);
        assert_eq!(
            ECodeSsaOpcode::IntSignedLess.evaluate(1, &[minus_one.clone(), seven.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::IntLess.evaluate(1, &[minus_one, seven.clone()]),
            Some(zero)
        );
    }

    #[test]
    fn evaluate_guards_width_mismatch_and_zero_divisor() {
        let wide = BitVec::from_u64(7, 32);
        let narrow = BitVec::from_u64(7, 16);
        assert_eq!(
            ECodeSsaOpcode::IntLess.evaluate(1, &[wide.clone(), narrow]),
            None
        );

        let zero = BitVec::from_u64(0, 32);
        assert_eq!(
            ECodeSsaOpcode::UnsignedDiv.evaluate(32, &[wide.clone(), zero.clone()]),
            None
        );
        assert_eq!(ECodeSsaOpcode::SignedRem.evaluate(32, &[wide, zero]), None);
    }

    #[test]
    fn evaluate_folds_division_and_bit_counts() {
        assert_eq!(
            ECodeSsaOpcode::UnsignedDiv
                .evaluate(32, &[BitVec::from_u64(20, 32), BitVec::from_u64(6, 32)]),
            Some(BitVec::from_u64(3, 32))
        );
        assert_eq!(
            ECodeSsaOpcode::UnsignedRem
                .evaluate(32, &[BitVec::from_u64(20, 32), BitVec::from_u64(6, 32)]),
            Some(BitVec::from_u64(2, 32))
        );
        assert_eq!(
            ECodeSsaOpcode::CountOnes.evaluate(32, &[BitVec::from_u64(0b1011, 32)]),
            Some(BitVec::from_u64(3, 32))
        );
        assert_eq!(
            ECodeSsaOpcode::CountLeadingZeros.evaluate(32, &[BitVec::from_u64(1, 32)]),
            Some(BitVec::from_u64(31, 32))
        );
    }

    #[test]
    fn evaluate_folds_carries_and_borrows() {
        let one = BitVec::from_u64(1, 1);
        let zero = BitVec::from_u64(0, 1);
        let max = BitVec::from_u64(u64::from(u32::MAX), 32);
        let signed_min = BitVec::from_u64(0x8000_0000, 32);
        let signed_max = BitVec::from_u64(0x7fff_ffff, 32);
        let unit = BitVec::from_u64(1, 32);

        assert_eq!(
            ECodeSsaOpcode::Carry.evaluate(1, &[max.clone(), unit.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::Carry.evaluate(1, &[unit.clone(), unit.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::Carry.evaluate(1, &[max.signed(), unit.clone()]),
            Some(one.clone())
        );

        assert_eq!(
            ECodeSsaOpcode::SignedCarry.evaluate(1, &[signed_max, unit.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::SignedCarry.evaluate(1, &[unit.clone(), unit.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::SignedBorrow.evaluate(1, &[signed_min, unit.clone()]),
            Some(one)
        );
        assert_eq!(
            ECodeSsaOpcode::SignedBorrow.evaluate(1, &[BitVec::from_u64(0, 32), unit]),
            Some(zero)
        );
    }

    #[test]
    fn evaluate_folds_boolean_and_signed_operations() {
        let one = BitVec::from_u64(1, 1);
        let zero = BitVec::from_u64(0, 1);

        assert_eq!(
            ECodeSsaOpcode::BoolAnd.evaluate(1, &[one.clone(), zero.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::BoolOr.evaluate(1, &[one.clone(), zero.clone()]),
            Some(one.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::BoolXor.evaluate(1, &[one.clone(), one.clone()]),
            Some(zero.clone())
        );
        assert_eq!(
            ECodeSsaOpcode::BoolNot.evaluate(1, std::slice::from_ref(&zero)),
            Some(one.clone())
        );

        let minus_twenty = BitVec::from_u64((-20i64) as u64, 32);
        let six = BitVec::from_u64(6, 32);
        assert_eq!(
            ECodeSsaOpcode::SignedDiv
                .evaluate(32, &[minus_twenty.clone(), six.clone()])
                .map(BitVec::unsigned),
            Some(BitVec::from_u64((-3i64) as u64, 32))
        );
        assert_eq!(
            ECodeSsaOpcode::SignedRem
                .evaluate(32, &[minus_twenty.clone(), six.clone()])
                .map(BitVec::unsigned),
            Some(BitVec::from_u64((-2i64) as u64, 32))
        );
        assert_eq!(
            ECodeSsaOpcode::IntSignedLessEqual.evaluate(1, &[minus_twenty, six]),
            Some(one)
        );
    }

    #[test]
    fn evaluate_leaves_extract_and_insert_unfolded() {
        let operand = BitVec::from_u64(0xff, 32);
        assert_eq!(
            ECodeSsaOpcode::Extract.evaluate(8, std::slice::from_ref(&operand)),
            None
        );
        assert_eq!(
            ECodeSsaOpcode::Insert.evaluate(32, &[operand.clone(), operand]),
            None
        );
    }
}
