use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use thiserror::Error;

use crate::context::ContextBitRange;
use crate::lifter::LiftingContextFactory;
use crate::operand::Operands;
use crate::pcode::{LiftingContext, PCodeBuilderContext, PCodeOp, Varnode};
use crate::wrap_offset;

#[derive(Clone, Copy)]
pub struct LanguageVariant {
    language: &'static Language,
    context: LiftingContextFactory,
    variant: &'static str,
}

impl PartialEq for LanguageVariant {
    fn eq(&self, other: &Self) -> bool {
        self.language == other.language && self.variant == other.variant
    }
}

impl Eq for LanguageVariant {}

impl PartialOrd for LanguageVariant {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanguageVariant {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.language
            .cmp(other.language)
            .then_with(|| self.variant.cmp(other.variant))
    }
}

impl Hash for LanguageVariant {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.language.hash(state);
        self.variant.hash(state);
    }
}

impl LanguageVariant {
    #[doc(hidden)]
    pub const fn new(
        variant: &'static str,
        language: &'static Language,
        context: LiftingContextFactory,
    ) -> Self {
        Self {
            language,
            context,
            variant,
        }
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn variant(&self) -> &'static str {
        self.variant
    }

    pub fn context(&self) -> LiftingContextFactory {
        self.context
    }
}

impl Debug for LanguageVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanguageVariant")
            .field("variant", &self.variant)
            .finish_non_exhaustive()
    }
}

impl Display for LanguageVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.language.processor(),
            if self.language.is_big_endian() {
                "BE"
            } else {
                "LE"
            },
            self.language.address_bits(),
            self.variant
        )
    }
}

pub struct LanguageId {
    processor: String,
    is_big: bool,
    bits: u32,
    variant: Option<String>,
}

impl LanguageId {
    pub fn processor(&self) -> &str {
        &self.processor
    }

    pub fn is_big_endian(&self) -> bool {
        self.is_big
    }

    pub fn is_little_endian(&self) -> bool {
        !self.is_big
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }
}

impl Display for LanguageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.processor,
            if self.is_big_endian() { "BE" } else { "LE" },
            self.bits,
            self.variant.as_deref().unwrap_or("default"),
        )
    }
}

#[derive(Debug, Error)]
pub enum LanguageParseError {
    #[error("could not parse processor name")]
    ParseProcessor,
    #[error("could not parse endian")]
    ParseEndian,
    #[error("could not parse bitness")]
    ParseBits,
    #[error("could not parse processor variant")]
    ParseVariant,
    #[error("could not parse architecture definition: incorrect format")]
    ParseFormat,
}

pub trait LanguageImpl {
    const ID: &'static str;

    const PROCESSOR: &'static str;
    const LITTLE_ENDIAN: bool;
    const VARIANT: &'static str;

    const ADDRESS_ALIGNMENT: usize;
    const ADDRESS_BITS: u32;
    const ADDRESS_SIZE: usize;
    const ADDRESS_UPPER_BOUND: u64;

    const CONSTANT_SPACE: u8;
    const DEFAULT_SPACE: u8;

    const REGISTER_SPACE: u8;
    const REGISTER_SPACE_SIZE: usize;

    const UNIQUE_MASK: u64;
    const UNIQUE_SPACE: u8;
    const UNIQUE_SPACE_SIZE: usize;

    const SPACE_WORD_SIZES: &'static [usize];
    const SPACE_UPPER_BOUNDS: &'static [u64];
    const SPACE_BY_NAME: fn(&str) -> Option<u8>;
    const SPACE_NAME: fn(u8) -> Option<&'static str>;

    const CONTEXT_VARIABLE_BY_NAME: fn(&str) -> Option<ContextBitRange>;

    const REGISTER_BY_NAME: fn(&str) -> Option<Varnode>;
    const REGISTER_NAME: fn(&Varnode) -> Option<&'static str>;

    const USER_OP_BY_NAME: fn(&str) -> Option<u16>;
    const USER_OP_BY_ID: fn(u16) -> Option<&'static str>;

    const RESOLVE: fn(u64, &[u8], &mut LiftingContext, bool) -> Option<usize>;
    const OPERANDS: fn(u64, &[u8], &mut LiftingContext, &mut Operands) -> Option<usize>;
    const DISASSEMBLE: fn(u64, &[u8], &mut LiftingContext, &mut String) -> Option<usize>;
    const LIFT: fn(u64, &[u8], &mut LiftingContext, &mut Vec<PCodeOp>) -> Option<usize>;
}

#[derive(Clone)]
pub struct Language {
    id: &'static str,

    processor: &'static str,
    little_endian: bool,
    variant: &'static str,

    address_alignment: usize,
    address_bits: u32,
    address_size: usize,
    address_upper_bound: u64,

    constant_space: u8,
    default_space: u8,

    register_space: u8,
    register_space_size: usize,

    unique_mask: u64,
    unique_space: u8,
    unique_space_size: usize,

    space_word_sizes: &'static [usize],
    space_upper_bounds: &'static [u64],
    space_by_name: fn(&str) -> Option<u8>,
    space_name: fn(u8) -> Option<&'static str>,

    context_variable_by_name: fn(&str) -> Option<ContextBitRange>,

    register_by_name: fn(&str) -> Option<Varnode>,
    register_name: fn(&Varnode) -> Option<&'static str>,

    user_op_by_name: fn(&str) -> Option<u16>,
    user_op_by_id: fn(u16) -> Option<&'static str>,

    resolve: fn(u64, &[u8], &mut LiftingContext, bool) -> Option<usize>,
    operands: fn(u64, &[u8], &mut LiftingContext, &mut Operands) -> Option<usize>,
    disassemble: fn(u64, &[u8], &mut LiftingContext, &mut String) -> Option<usize>,
    lift: fn(u64, &[u8], &mut LiftingContext, &mut Vec<PCodeOp>) -> Option<usize>,
}

impl Debug for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Language")
            .field("id", &self.id)
            .field("address_alignment", &self.address_alignment)
            .field("address_bits", &self.address_bits)
            .finish_non_exhaustive()
    }
}

impl Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id)
    }
}

impl PartialEq for Language {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Language {}

impl Ord for Language {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(other.id)
    }
}

impl PartialOrd for Language {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Language {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

pub struct LanguageFormatter<'a, T> {
    pub(crate) language: &'static Language,
    pub(crate) value: &'a T,
}

impl<'a, T> LanguageFormatter<'a, T> {
    pub fn new(language: &'static Language, value: &'a T) -> Self {
        Self { language, value }
    }

    pub fn wrap<'b, U>(&self, value: &'b U) -> LanguageFormatter<'b, U> {
        LanguageFormatter {
            language: self.language,
            value,
        }
    }
}

impl Language {
    pub const fn new<L: LanguageImpl>() -> Self {
        Self {
            id: L::ID,

            processor: L::PROCESSOR,
            little_endian: L::LITTLE_ENDIAN,
            variant: L::VARIANT,

            address_alignment: L::ADDRESS_ALIGNMENT,
            address_bits: L::ADDRESS_BITS,
            address_size: L::ADDRESS_SIZE,
            address_upper_bound: L::ADDRESS_UPPER_BOUND,

            constant_space: L::CONSTANT_SPACE,
            default_space: L::DEFAULT_SPACE,

            register_space: L::REGISTER_SPACE,
            register_space_size: L::REGISTER_SPACE_SIZE,

            unique_mask: L::UNIQUE_MASK,
            unique_space: L::UNIQUE_SPACE,
            unique_space_size: L::UNIQUE_SPACE_SIZE,

            space_word_sizes: L::SPACE_WORD_SIZES,
            space_upper_bounds: L::SPACE_UPPER_BOUNDS,
            space_by_name: L::SPACE_BY_NAME,
            space_name: L::SPACE_NAME,

            context_variable_by_name: L::CONTEXT_VARIABLE_BY_NAME,

            register_by_name: L::REGISTER_BY_NAME,
            register_name: L::REGISTER_NAME,

            user_op_by_name: L::USER_OP_BY_NAME,
            user_op_by_id: L::USER_OP_BY_ID,

            resolve: L::RESOLVE,
            operands: L::OPERANDS,
            disassemble: L::DISASSEMBLE,
            lift: L::LIFT,
        }
    }

    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn processor(&self) -> &'static str {
        self.processor
    }

    pub fn is_big_endian(&self) -> bool {
        !self.little_endian
    }

    pub fn is_little_endian(&self) -> bool {
        self.little_endian
    }

    pub fn variant(&self) -> &'static str {
        self.variant
    }

    pub fn address_alignment(&self) -> usize {
        self.address_alignment
    }

    pub fn address_bits(&self) -> u32 {
        self.address_bits
    }

    pub fn address_size(&self) -> usize {
        self.address_size
    }

    pub fn address_upper_bound(&self) -> u64 {
        self.address_upper_bound
    }

    pub fn constant_space(&self) -> u8 {
        self.constant_space
    }

    pub fn in_constant_space(&self, varnode: &Varnode) -> bool {
        self.constant_space == varnode.space()
    }

    pub fn default_space(&self) -> u8 {
        self.default_space
    }

    pub fn in_default_space(&self, varnode: &Varnode) -> bool {
        self.default_space == varnode.space()
    }

    pub fn register_space(&self) -> u8 {
        self.register_space
    }

    pub fn in_register_space(&self, varnode: &Varnode) -> bool {
        self.register_space == varnode.space()
    }

    pub fn register_space_size(&self) -> usize {
        self.register_space_size
    }

    pub fn unique_mask(&self) -> u64 {
        self.unique_mask
    }

    pub fn unique_space(&self) -> u8 {
        self.unique_space
    }

    pub fn in_unique_space(&self, varnode: &Varnode) -> bool {
        self.unique_space == varnode.space()
    }

    pub fn unique_space_size(&self) -> usize {
        self.unique_space_size
    }

    pub fn space_name(&self, space: u8) -> Option<&'static str> {
        (self.space_name)(space)
    }

    pub fn space_by_name(&self, name: impl AsRef<str>) -> Option<u8> {
        (self.space_by_name)(name.as_ref())
    }

    pub fn space_word_size(&self, space: u8) -> Option<usize> {
        self.space_word_sizes.get(space as usize).copied()
    }

    pub fn space_upper_bound(&self, space: u8) -> Option<u64> {
        self.space_upper_bounds.get(space as usize).copied()
    }

    pub fn wrap_offset(&self, space: u8, offset: u64) -> Option<u64> {
        self.space_upper_bound(space)
            .map(|highest| wrap_offset(highest, offset))
    }

    pub fn wrap_offset_in_default_space(&self, offset: u64) -> u64 {
        self.wrap_offset(self.default_space(), offset)
            .expect("default space exists")
    }

    pub fn context_variable_by_name(&self, name: impl AsRef<str>) -> Option<ContextBitRange> {
        (self.context_variable_by_name)(name.as_ref())
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Varnode> {
        (self.register_by_name)(name.as_ref())
    }

    pub fn register_name(&self, vnd: &Varnode) -> Option<&'static str> {
        (self.register_name)(vnd)
    }

    pub fn user_op_by_name(&self, name: impl AsRef<str>) -> Option<u16> {
        (self.user_op_by_name)(name.as_ref())
    }

    pub fn user_op_by_id(&self, id: u16) -> Option<&'static str> {
        (self.user_op_by_id)(id)
    }

    pub fn builder(&self) -> PCodeBuilderContext {
        PCodeBuilderContext::new(self.unique_mask)
    }

    pub fn display<'a, T>(&'static self, value: &'a T) -> LanguageFormatter<'a, T> {
        LanguageFormatter::new(self, value)
    }

    pub fn resolve(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        apply_commits: bool,
    ) -> Option<usize> {
        (self.resolve)(address, bytes.as_ref(), context, apply_commits)
    }

    pub fn operands(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        operands: &mut Operands,
    ) -> Option<usize> {
        (self.operands)(address, bytes.as_ref(), context, operands)
    }

    pub fn disassemble(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        disassembly: &mut String,
    ) -> Option<usize> {
        (self.disassemble)(address, bytes.as_ref(), context, disassembly)
    }

    pub fn lift(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        operations: &mut Vec<PCodeOp>,
    ) -> Option<usize> {
        (self.lift)(address, bytes.as_ref(), context, operations)
    }
}

impl FromStr for LanguageId {
    type Err = LanguageParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');

        let Some(processor) = parts.next().map(str::trim) else {
            return Err(LanguageParseError::ParseFormat);
        };

        if processor.is_empty() {
            return Err(LanguageParseError::ParseFormat);
        }

        let Some(endian) = parts.next().map(str::trim) else {
            return Err(LanguageParseError::ParseFormat);
        };

        let is_big = match endian {
            "le" | "LE" => false,
            "be" | "BE" => true,
            _ => {
                return Err(LanguageParseError::ParseEndian);
            }
        };

        let Some(bits) = parts.next().map(str::trim) else {
            return Err(LanguageParseError::ParseFormat);
        };

        let bits = match bits.parse::<u32>() {
            Ok(bits) if [8, 16, 32, 64].contains(&bits) => bits,
            _ => {
                return Err(LanguageParseError::ParseBits);
            }
        };

        let variant = parts
            .next()
            .map(str::trim)
            .and_then(|v| (!v.is_empty()).then_some(v))
            .map(ToOwned::to_owned);

        Ok(Self {
            processor: processor.to_owned(),
            is_big,
            bits,
            variant,
        })
    }
}
