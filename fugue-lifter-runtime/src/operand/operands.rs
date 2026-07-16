use std::fmt;
use std::ops::Range;

use bitflags::bitflags;

use crate::language::Language;
use crate::pcode::Varnode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Register {
    name: &'static str,
    varnode: Varnode,
}

impl Register {
    fn new(name: &'static str, varnode: Varnode) -> Self {
        Self { name, varnode }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn size(&self) -> u16 {
        self.varnode.size
    }

    pub fn varnode(&self) -> Varnode {
        self.varnode
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scalar {
    value: i64,
    bits: u16,
    signed: bool,
}

impl Scalar {
    fn new(value: i64, bits: u16, signed: bool) -> Self {
        Self {
            value,
            bits,
            signed,
        }
    }

    pub fn value(&self) -> i64 {
        self.value
    }

    pub fn bits(&self) -> u16 {
        self.bits
    }

    pub fn signed(&self) -> bool {
        self.signed
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.signed && self.value < 0 {
            write!(f, "-{:#x}", self.value.unsigned_abs())
        } else {
            write!(f, "{:#x}", self.value as u64)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandPiece {
    Text(&'static str),
    Register(Register),
    Scalar(Scalar),
    Address(u64),
}

impl OperandPiece {
    pub(crate) fn from_varnode(
        language: &'static Language,
        name: &'static str,
        space: u8,
        offset: u64,
        size: u16,
    ) -> Self {
        let data = language.data();
        if space == data.constant_space {
            Self::Scalar(Scalar::new(offset as i64, size.saturating_mul(8), false))
        } else if space == data.default_space {
            Self::Address(offset)
        } else {
            Self::Register(Register::new(name, Varnode::new(space, offset, size)))
        }
    }

    pub(crate) fn register(language: &'static Language, name: &'static str) -> Self {
        match language.register_by_name(name) {
            Some(varnode) => Self::Register(Register::new(name, varnode)),
            None => Self::Text(name),
        }
    }

    pub(crate) fn scalar(value: i64, bits: Option<&Range<u32>>, signed: bool) -> Self {
        let bits = bits
            .map(|bits| u16::try_from(bits.end - bits.start).unwrap_or(u16::MAX))
            .unwrap_or(0);
        Self::Scalar(Scalar::new(value, bits, signed))
    }
}

impl fmt::Display for OperandPiece {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(text),
            Self::Register(register) => f.write_str(register.name()),
            Self::Scalar(scalar) => write!(f, "{scalar}"),
            Self::Address(offset) => write!(f, "{offset:#x}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandKind {
    Register,
    Scalar,
    CodeAddress,
    DataAddress,
    Dynamic,
}

impl OperandKind {
    fn classify(pieces: &[OperandPiece]) -> Self {
        let has = |select: fn(&OperandPiece) -> bool| pieces.iter().any(select);
        match pieces {
            [] => Self::Dynamic,
            [OperandPiece::Register(_)] => Self::Register,
            [OperandPiece::Scalar(_)] => Self::Scalar,
            [OperandPiece::Address(_)] => Self::DataAddress,
            _ if has(|piece| matches!(piece, OperandPiece::Register(_))) => Self::Dynamic,
            _ if has(|piece| matches!(piece, OperandPiece::Address(_))) => Self::DataAddress,
            _ if has(|piece| matches!(piece, OperandPiece::Scalar(_))) => Self::Scalar,
            _ => Self::Dynamic,
        }
    }
}

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct OperandAccess: u8 {
        const READ = 1;
        const WRITE = 2;
        const INDIRECT = 4;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OperandInfo {
    pieces: Range<usize>,
    kind: OperandKind,
    access: OperandAccess,
    bits: Option<Range<u32>>,
}

impl OperandInfo {
    pub(crate) fn kind(&self) -> OperandKind {
        self.kind
    }

    pub(crate) fn set_kind(&mut self, kind: OperandKind) {
        self.kind = kind;
    }

    pub(crate) fn access(&self) -> OperandAccess {
        self.access
    }

    pub(crate) fn insert_access(&mut self, access: OperandAccess) {
        self.access.insert(access);
    }

    pub(crate) fn pieces(&self) -> Range<usize> {
        self.pieces.clone()
    }

    pub(crate) fn set_pieces(&mut self, pieces: Range<usize>) {
        self.pieces = pieces;
    }

    pub(crate) fn bits(&self) -> Option<&Range<u32>> {
        self.bits.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Operands {
    mnemonic: String,
    pieces: Vec<OperandPiece>,
    operands: Vec<OperandInfo>,
    separators: String,
    separator_ranges: Vec<Range<usize>>,
    separator_mark: usize,
    piece_mark: usize,
    bits: Option<Range<u32>>,
}

impl Operands {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.mnemonic.clear();
        self.pieces.clear();
        self.operands.clear();
        self.separators.clear();
        self.separator_ranges.clear();
        self.separator_mark = 0;
        self.piece_mark = 0;
        self.bits = None;
    }

    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    pub fn len(&self) -> usize {
        self.operands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operands.is_empty()
    }

    pub fn operand(&self, index: usize) -> Option<OperandRef<'_>> {
        let info = self.operands.get(index)?;
        Some(OperandRef::new(&self.pieces[info.pieces()], info))
    }

    pub fn iter(&self) -> impl Iterator<Item = OperandRef<'_>> {
        self.operands
            .iter()
            .map(|info| OperandRef::new(&self.pieces[info.pieces()], info))
    }

    pub fn separator(&self, index: usize) -> Option<&str> {
        self.separator_ranges
            .get(index)
            .map(|range| &self.separators[range.clone()])
    }

    pub(crate) fn mnemonic_mut(&mut self) -> &mut String {
        &mut self.mnemonic
    }

    pub(crate) fn push_separator(&mut self, separator: &str) {
        self.separators.push_str(separator);
    }

    pub(crate) fn begin_operand(&mut self) {
        self.separator_ranges
            .push(self.separator_mark..self.separators.len());
        self.separator_mark = self.separators.len();
        self.piece_mark = self.pieces.len();
        self.bits = None;
    }

    pub(crate) fn push_piece(&mut self, piece: OperandPiece) {
        self.pieces.push(piece);
    }

    pub(crate) fn merge_bits(&mut self, bits: Option<Range<u32>>) {
        if let Some(bits) = bits {
            self.bits = Some(match self.bits.take() {
                Some(existing) => existing.start.min(bits.start)..existing.end.max(bits.end),
                None => bits,
            });
        }
    }

    pub(crate) fn finish_operand(&mut self) {
        let pieces = self.piece_mark..self.pieces.len();
        let kind = OperandKind::classify(&self.pieces[pieces.clone()]);
        self.operands.push(OperandInfo {
            pieces,
            kind,
            access: OperandAccess::empty(),
            bits: self.bits.take(),
        });
        self.piece_mark = self.pieces.len();
    }

    pub(crate) fn finish(&mut self) {
        self.separator_ranges
            .push(self.separator_mark..self.separators.len());
        self.separator_mark = self.separators.len();
    }

    pub(crate) fn parts_mut(&mut self) -> (&mut Vec<OperandPiece>, &mut [OperandInfo]) {
        (&mut self.pieces, &mut self.operands)
    }
}

impl fmt::Display for Operands {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.mnemonic)?;
        for (index, operand) in self.iter().enumerate() {
            if let Some(separator) = self.separator(index) {
                f.write_str(separator)?;
            }
            write!(f, "{operand}")?;
        }
        if let Some(separator) = self.separator(self.len()) {
            f.write_str(separator)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OperandRef<'a> {
    pieces: &'a [OperandPiece],
    info: &'a OperandInfo,
}

impl<'a> OperandRef<'a> {
    fn new(pieces: &'a [OperandPiece], info: &'a OperandInfo) -> Self {
        Self { pieces, info }
    }

    pub fn pieces(&self) -> &'a [OperandPiece] {
        self.pieces
    }

    pub fn kind(&self) -> OperandKind {
        self.info.kind()
    }

    pub fn access(&self) -> OperandAccess {
        self.info.access()
    }

    pub fn range(&self) -> Option<&'a Range<u32>> {
        self.info.bits()
    }

    pub fn register(&self) -> Option<Register> {
        match self.pieces {
            [OperandPiece::Register(register)] => Some(*register),
            _ => None,
        }
    }

    pub fn scalar(&self) -> Option<Scalar> {
        match self.pieces {
            [OperandPiece::Scalar(scalar)] => Some(*scalar),
            _ => None,
        }
    }

    pub fn address(&self) -> Option<u64> {
        match self.pieces {
            [OperandPiece::Address(offset)] => Some(*offset),
            _ => None,
        }
    }

    pub fn is_read(&self) -> bool {
        self.access().contains(OperandAccess::READ)
    }

    pub fn is_write(&self) -> bool {
        self.access().contains(OperandAccess::WRITE)
    }

    pub fn is_indirect(&self) -> bool {
        self.access().contains(OperandAccess::INDIRECT)
    }
}

impl fmt::Display for OperandRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for piece in self.pieces {
            write!(f, "{piece}")?;
        }
        Ok(())
    }
}
