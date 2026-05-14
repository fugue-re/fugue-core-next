use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use thiserror::Error;

use crate::constructor::Constructor;
use crate::context::{ContextBitRange, ContextDatabase};
use crate::operand::OperandFilter;
use crate::operand::Operands;
use crate::pattern::PatternOp;
use crate::pcode::{LiftingContext, PCodeBuilderContext, PCodeOp, Varnode};
use crate::resolve::DecisionNode;
use crate::space::{AddressSpace, AddressSpaceKind};
use crate::symbol::Symbol;
use crate::template::{ConstTpl, ConstructTpl, HandleTpl, OpTpl, VarnodeTpl};
use crate::{calculate_mask, entry, wrap_offset, LiftingContextState};

#[derive(Clone, Copy)]
pub struct LanguageVariant {
    language: &'static Language,
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
    pub const fn new(variant: &'static str, language: &'static Language) -> Self {
        Self { language, variant }
    }

    pub fn language(&self) -> &'static Language {
        self.language
    }

    pub fn variant(&self) -> &'static str {
        self.variant
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

pub struct LanguageData {
    pub root_dtree: u16,

    pub address_size: usize,
    pub constant_space: u8,
    pub default_space: u8,
    pub unique_space: u8,

    pub spaces: &'static [AddressSpace],

    pub constructors: &'static [Constructor],
    pub decision_trees: &'static [DecisionNode],
    pub operand_filters: &'static [OperandFilter],
    pub pattern_expressions: &'static [PatternOp],
    pub symbols: &'static [Symbol],

    pub const_templates: &'static [ConstTpl],
    pub construct_templates: &'static [ConstructTpl],
    pub handle_templates: &'static [HandleTpl],
    pub op_templates: &'static [OpTpl],
    pub varnode_templates: &'static [VarnodeTpl],
}

impl LanguageData {
    #[inline(always)]
    pub(crate) fn resolve_constructor(
        &'static self,
        id: u16,
        state: &mut LiftingContextState,
    ) -> Option<&'static Constructor> {
        self.decision_trees[id as usize].resolve(self, state)
    }

    #[inline(always)]
    pub(crate) fn resolve_instruction(
        &'static self,
        state: &mut LiftingContextState,
    ) -> Option<&'static Constructor> {
        unsafe {
            let ctor = self.decision_trees[self.root_dtree as usize].resolve(self, state)?;
            ctor.resolve_operands(self, state)?;
            Some(ctor)
        }
    }

    #[inline(always)]
    pub(crate) fn resolve_state(
        &'static self,
        state: &mut LiftingContextState,
    ) -> Option<&'static Constructor> {
        unsafe {
            let ctor = self.resolve_instruction(state)?;
            ctor.resolve_handles(self, state)?;
            state.inputs.input.base_state();
            state.apply_commits(self);
            Some(ctor)
        }
    }

    #[inline(always)]
    pub fn space_upper_bound(&self, space: u8) -> u64 {
        self.spaces[space as usize].upper_bound()
    }

    #[inline(always)]
    pub fn space_word_size(&self, space: u8) -> usize {
        self.spaces[space as usize].word_size()
    }

    #[inline(always)]
    pub fn space_kind(&self, space: u8) -> AddressSpaceKind {
        self.spaces[space as usize].kind()
    }

    #[inline(always)]
    pub fn space_location_offset(
        &self,
        unique_offset: u64,
        space: u8,
        offset: u64,
        size: u16,
    ) -> u64 {
        let info = &self.spaces[space as usize];
        match info.kind() {
            AddressSpaceKind::Constant => offset & calculate_mask(size as usize),
            AddressSpaceKind::Unique => offset | unique_offset,
            AddressSpaceKind::Default | AddressSpaceKind::Other => {
                wrap_offset(info.upper_bound(), offset)
            }
        }
    }
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

    const REGISTERS: &'static [(&'static str, Varnode)];
    const REGISTER_RANGES: &'static [(u64, u16, &'static str)];
    const USER_OPS: &'static [&'static str];
    const SPACE_NAMES: &'static [&'static str];
    const CONTEXT_VARS: &'static [(&'static str, ContextBitRange)];
    const CONTEXT_DEFAULTS: &'static [(&'static str, u32)];

    const DATA: &'static LanguageData;
}

#[derive(Clone)]
pub struct Language {
    pub(crate) id: &'static str,

    pub(crate) processor: &'static str,
    pub(crate) little_endian: bool,
    pub(crate) variant: &'static str,

    pub(crate) address_alignment: usize,
    pub(crate) address_bits: u32,
    pub(crate) address_size: usize,
    pub(crate) address_upper_bound: u64,

    pub(crate) constant_space: u8,
    pub(crate) default_space: u8,

    pub(crate) register_space: u8,
    pub(crate) register_space_size: usize,

    pub(crate) unique_mask: u64,
    pub(crate) unique_space: u8,
    pub(crate) unique_space_size: usize,

    pub(crate) space_word_sizes: &'static [usize],
    pub(crate) space_upper_bounds: &'static [u64],

    pub(crate) registers: &'static [(&'static str, Varnode)],
    pub(crate) register_ranges: &'static [(u64, u16, &'static str)],
    pub(crate) user_ops: &'static [&'static str],
    pub(crate) space_names: &'static [&'static str],
    pub(crate) context_vars: &'static [(&'static str, ContextBitRange)],
    pub(crate) context_defaults: &'static [(&'static str, u32)],

    pub(crate) data: &'static LanguageData,
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

            registers: L::REGISTERS,
            register_ranges: L::REGISTER_RANGES,
            user_ops: L::USER_OPS,
            space_names: L::SPACE_NAMES,
            context_vars: L::CONTEXT_VARS,
            context_defaults: L::CONTEXT_DEFAULTS,

            data: L::DATA,
        }
    }

    #[inline(always)]
    pub fn data(&self) -> &'static LanguageData {
        self.data
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
        self.space_names.get(space as usize).copied()
    }

    pub fn space_by_name(&self, name: impl AsRef<str>) -> Option<u8> {
        let name = name.as_ref();
        self.space_names
            .iter()
            .position(|n| *n == name)
            .map(|p| p as u8)
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
        let name = name.as_ref();
        self.context_vars
            .binary_search_by_key(&name, |(n, _)| *n)
            .ok()
            .map(|idx| self.context_vars[idx].1)
    }

    pub fn context_variables(&self) -> &'static [(&'static str, ContextBitRange)] {
        self.context_vars
    }

    pub fn context_defaults(&self) -> &'static [(&'static str, u32)] {
        self.context_defaults
    }

    pub fn default_context(&self) -> ContextDatabase {
        let mut db = ContextDatabase::new(self.address_upper_bound, self.address_alignment);
        let bits_per_word = u32::BITS as usize;
        for (name, bits) in self.context_vars {
            let word_offset = bits.word() * bits_per_word;
            db.register_variable(
                *name,
                word_offset + bits.start_bit(),
                word_offset + bits.end_bit(),
            );
        }
        for (name, value) in self.context_defaults {
            if let Some(bits) = self.context_variable_by_name(name) {
                db.set_variable_default_by_bits(bits, *value);
            }
        }
        db
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Varnode> {
        let name = name.as_ref();
        self.registers
            .binary_search_by_key(&name, |(n, _)| *n)
            .ok()
            .map(|idx| self.registers[idx].1)
    }

    pub fn register_name(&self, vnd: &Varnode) -> Option<&'static str> {
        if vnd.space() != self.register_space {
            return None;
        }
        let key = (vnd.offset(), vnd.size);
        self.register_ranges
            .binary_search_by_key(&key, |(off, sz, _)| (*off, *sz))
            .ok()
            .map(|idx| self.register_ranges[idx].2)
    }

    pub fn user_op_by_name(&self, name: impl AsRef<str>) -> Option<u16> {
        let name = name.as_ref();
        self.user_ops
            .iter()
            .position(|n| *n == name)
            .map(|p| p as u16)
    }

    pub fn user_op_by_id(&self, id: u16) -> Option<&'static str> {
        self.user_ops.get(id as usize).copied()
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
        entry::resolve(address, bytes.as_ref(), context, apply_commits)
    }

    pub fn operands(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        operands: &mut Operands,
    ) -> Option<usize> {
        entry::operands(address, bytes.as_ref(), context, operands)
    }

    pub fn disassemble(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        disassembly: &mut String,
    ) -> Option<usize> {
        entry::disassemble(address, bytes.as_ref(), context, disassembly)
    }

    pub fn disassemble_parts(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        mnemonic: &mut String,
        operands: &mut String,
    ) -> Option<usize> {
        entry::disassemble_parts(address, bytes.as_ref(), context, mnemonic, operands)
    }

    pub fn lift(
        &self,
        address: u64,
        bytes: impl AsRef<[u8]>,
        context: &mut LiftingContext,
        operations: &mut Vec<PCodeOp>,
    ) -> Option<usize> {
        entry::lift(address, bytes.as_ref(), context, operations)
    }
}

#[cfg(feature = "dynamic")]
mod load {
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::path::Path;

    use flate2::read::GzDecoder;
    use rkyv::rancor::Error as RkyvError;

    use super::{Language, LanguageId};
    use crate::dynamic::blob::language::Language as LanguageBlob;
    use crate::dynamic::{build, install, registry, LanguageLoadError};

    impl Language {
        pub fn from_bytes(bytes: &[u8]) -> Result<&'static Language, LanguageLoadError> {
            let blob = rkyv::from_bytes::<LanguageBlob, RkyvError>(bytes)
                .map_err(LanguageLoadError::Deserialise)?;
            install_blob(blob)
        }

        pub fn from_file(path: impl AsRef<Path>) -> Result<&'static Language, LanguageLoadError> {
            let path = path.as_ref();
            let file = File::open(path)
                .map_err(|source| LanguageLoadError::io("open", path.to_path_buf(), source))?;
            let mut reader = GzDecoder::new(BufReader::new(file));
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|source| LanguageLoadError::io("read", path.to_path_buf(), source))?;
            Self::from_bytes(&bytes)
        }

        pub fn from_sleigh(
            specs: impl AsRef<Path>,
            id: &str,
        ) -> Result<&'static Language, LanguageLoadError> {
            let blob = build::build(specs, id)?;
            install_blob(blob)
        }

        pub fn lookup(id: &LanguageId) -> Option<&'static Language> {
            registry::lookup(id)
        }
    }

    fn install_blob(blob: LanguageBlob) -> Result<&'static Language, LanguageLoadError> {
        let id_str = blob.id.as_ref();
        let language_id = id_str
            .parse::<LanguageId>()
            .map_err(|err| LanguageLoadError::LanguageId(id_str.to_owned(), err))?;
        Ok(registry::intern_or_install(language_id, || {
            install::install(blob)
        }))
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
