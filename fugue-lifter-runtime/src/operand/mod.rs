use crate::language::LanguageData;
use crate::pattern::PatternExpression;
use crate::pcode::LiftingContextState;

mod correlate;
mod operands;

pub use correlate::OperandsContext;
pub use operands::{
    OperandAccess, OperandKind, OperandPiece, OperandRef, Operands, Register, Scalar,
};

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum OperandResolver {
    None,
    Constructor(u16),
    Filter(u16),
}

pub struct OperandFilter {
    pub pattern: PatternExpression,
    pub indices: &'static [u16],
    pub limit: u16,
}

impl OperandFilter {
    /// # Safety
    ///
    /// Called from generated code which ensures validity of arguments and state.
    #[inline]
    pub unsafe fn validate(
        &self,
        data: &'static LanguageData,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        unsafe {
            let index = u16::try_from(self.pattern.resolve(data, input)?).ok()?;
            if index >= self.limit || self.indices.contains(&index) {
                None
            } else {
                Some(())
            }
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum OperandHandleResolver {
    None,
    Symbol(u16),
    Expression(PatternExpression),
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(resolver = OperandArchiveResolver)]
pub struct Operand {
    pub resolver: OperandResolver,
    pub handle_resolver: OperandHandleResolver,
    pub offset_base: Option<usize>,
    pub offset_rela: usize,
    pub minimum_length: usize,
}
