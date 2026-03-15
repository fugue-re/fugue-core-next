use std::ops::Range;

use crate::pattern::PatternExpression;
use crate::{ConstructorResolver, LiftingContextState};

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
    pub unsafe fn validate<R: ConstructorResolver>(
        &self,
        input: &mut LiftingContextState,
    ) -> Option<()> {
        let index = u16::try_from(self.pattern.resolve::<R>(input)?).ok()?;
        if index >= self.limit || self.indices.contains(&index) {
            None
        } else {
            Some(())
        }
    }
}

pub enum OperandHandleResolver {
    None,
    Symbol(u16),
    Expression(PatternExpression),
}

pub struct Operand {
    pub resolver: OperandResolver,
    pub handle_resolver: OperandHandleResolver,
    pub offset_base: Option<usize>,
    pub offset_rela: usize,
    pub minimum_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OperandValue {
    Address(u64),
    Group(Operands),
    Symbol(&'static str),
    Value(i64),
}

impl From<u64> for OperandValue {
    fn from(value: u64) -> Self {
        Self::Address(value)
    }
}

impl From<&'static str> for OperandValue {
    fn from(value: &'static str) -> Self {
        Self::Symbol(value)
    }
}

impl From<i64> for OperandValue {
    fn from(value: i64) -> Self {
        Self::Value(value)
    }
}

impl OperandValue {
    pub(crate) fn from_varnode<R: ConstructorResolver>(
        name: &'static str,
        space: u8,
        offset: u64,
    ) -> Self {
        if space == R::CONSTANT_SPACE {
            Self::Value(offset as _)
        } else if space == R::DEFAULT_SPACE {
            Self::Address(offset)
        } else {
            Self::Symbol(name)
        }
    }

    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Address(addr) => Some(*addr),
            _ => None,
        }
    }

    // A group is a collection of operands within an instruction or operand. For
    // example, `MOV EAX, dword ptr [EBX + ECX]`, we may have two operands at
    // the top-level, `EAX` and a group [EBX, ECX].
    pub fn group(&self) -> Option<&Operands> {
        match self {
            Self::Group(ops) => Some(ops),
            _ => None,
        }
    }

    // A symbol may be a register, to check we need to match against the
    // list of known registers for a language.
    pub fn symbol(&self) -> Option<&'static str> {
        match self {
            Self::Symbol(reg) => Some(reg),
            _ => None,
        }
    }

    // A value may be an address, to check we need to infer it based on the
    // analysed binary.
    pub fn value(&self) -> Option<i64> {
        match self {
            Self::Value(val) => Some(*val),
            _ => None,
        }
    }

    pub fn get(&self, index: usize) -> Option<&OperandData> {
        self.group()?.get(index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperandData {
    value: OperandValue,
    range: Option<Range<u32>>,
}

impl<T> From<T> for OperandData
where
    T: Into<OperandValue>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl OperandData {
    pub fn new(value: impl Into<OperandValue>) -> Self {
        Self::new_with(value, None)
    }

    pub fn new_with(value: impl Into<OperandValue>, range: impl Into<Option<Range<u32>>>) -> Self {
        Self {
            value: value.into(),
            range: range.into(),
        }
    }

    pub fn address(&self) -> Option<u64> {
        self.value.address()
    }

    pub fn group(&self) -> Option<&Operands> {
        self.value.group()
    }

    pub fn symbol(&self) -> Option<&'static str> {
        self.value.symbol()
    }

    pub fn value(&self) -> Option<i64> {
        self.value.value()
    }

    pub fn range(&self) -> Option<&Range<u32>> {
        self.range.as_ref()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Operands(Vec<OperandData>);

impl Operands {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, opnd: impl Into<OperandData>) {
        self.0.push(opnd.into());
    }

    pub fn push_with(
        &mut self,
        opnd: impl Into<OperandValue>,
        range: impl Into<Option<Range<u32>>>,
    ) {
        self.0.push(OperandData::new_with(opnd, range));
    }

    pub fn append(&mut self, mut opnds: Self) {
        match opnds.len() {
            1 => {
                self.push(opnds.0.pop().unwrap());
            }
            n if n > 0 => {
                self.push(OperandData::new(OperandValue::Group(opnds)));
            }
            _ => (),
        }
    }

    pub fn get(&self, index: usize) -> Option<&OperandData> {
        self.0.get(index)
    }

    pub fn into_iter(self) -> impl ExactSizeIterator<Item = OperandData> {
        self.0.into_iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
