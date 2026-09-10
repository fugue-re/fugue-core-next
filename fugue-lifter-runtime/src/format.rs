use std::fmt::{self, Write};
use std::ops::Range;

use arrayvec::ArrayString;

use crate::operand::OperandPiece;

pub trait InstructionFormatter {
    fn write_mnemonic(&mut self, mnemonic: &str) -> fmt::Result;

    fn write_literal(&mut self, text: &str) -> fmt::Result;

    fn write_register(&mut self, name: &str) -> fmt::Result;

    fn write_value(&mut self, value: i64, text: &str) -> fmt::Result;

    fn write_address(&mut self, address: u64, text: &str) -> fmt::Result;

    fn begin_operand(&mut self) -> fmt::Result;

    fn end_operand(&mut self) -> fmt::Result;
}

#[derive(Clone, Copy)]
pub(crate) enum InstructionSection {
    Mnemonic,
    Operand,
}

pub(crate) enum InstructionFormatError {
    Formatting(fmt::Error),
    Unresolved,
}

pub(crate) trait InstructionWriter {
    fn write_mnemonic_piece(&mut self, piece: OperandPiece) -> fmt::Result;

    fn write_separator(&mut self, separator: &str) -> fmt::Result;

    fn write_operand_piece(&mut self, piece: OperandPiece, bits: Option<Range<u32>>)
    -> fmt::Result;

    fn begin_operand(&mut self) -> fmt::Result;

    fn end_operand(&mut self) -> fmt::Result;

    fn finish_instruction(&mut self) -> fmt::Result;
}

impl From<fmt::Error> for InstructionFormatError {
    fn from(error: fmt::Error) -> Self {
        Self::Formatting(error)
    }
}

impl InstructionSection {
    pub(crate) fn write<W: InstructionWriter + ?Sized>(
        self,
        writer: &mut W,
        piece: OperandPiece,
        bits: Option<Range<u32>>,
    ) -> fmt::Result {
        match self {
            Self::Mnemonic => writer.write_mnemonic_piece(piece),
            Self::Operand => writer.write_operand_piece(piece, bits),
        }
    }
}

impl<F: InstructionFormatter + ?Sized> InstructionWriter for F {
    fn write_mnemonic_piece(&mut self, piece: OperandPiece) -> fmt::Result {
        match piece {
            OperandPiece::Text(text) => self.write_mnemonic(text),
            OperandPiece::Register(register) => self.write_mnemonic(register.name()),
            OperandPiece::Scalar(scalar) => {
                let mut text = ArrayString::<32>::new();
                write!(&mut text, "{scalar}")?;
                self.write_mnemonic(&text)
            }
            OperandPiece::Address(address) => {
                let mut text = ArrayString::<32>::new();
                write!(&mut text, "{address:#x}")?;
                self.write_mnemonic(&text)
            }
        }
    }

    fn write_separator(&mut self, separator: &str) -> fmt::Result {
        self.write_literal(separator)
    }

    fn write_operand_piece(
        &mut self,
        piece: OperandPiece,
        _bits: Option<Range<u32>>,
    ) -> fmt::Result {
        match piece {
            OperandPiece::Text(text) => self.write_literal(text),
            OperandPiece::Register(register) => self.write_register(register.name()),
            OperandPiece::Scalar(scalar) => {
                let mut text = ArrayString::<32>::new();
                write!(&mut text, "{scalar}")?;
                self.write_value(scalar.value(), &text)
            }
            OperandPiece::Address(address) => {
                let mut text = ArrayString::<32>::new();
                write!(&mut text, "{address:#x}")?;
                self.write_address(address, &text)
            }
        }
    }

    fn begin_operand(&mut self) -> fmt::Result {
        InstructionFormatter::begin_operand(self)
    }

    fn end_operand(&mut self) -> fmt::Result {
        InstructionFormatter::end_operand(self)
    }

    fn finish_instruction(&mut self) -> fmt::Result {
        Ok(())
    }
}

pub(crate) struct InstructionText<W> {
    writer: W,
}

impl<W> InstructionText<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: fmt::Write> InstructionWriter for InstructionText<W> {
    fn write_mnemonic_piece(&mut self, piece: OperandPiece) -> fmt::Result {
        write!(self.writer, "{piece}")
    }

    fn write_separator(&mut self, separator: &str) -> fmt::Result {
        self.writer.write_str(separator)
    }

    fn write_operand_piece(
        &mut self,
        piece: OperandPiece,
        _bits: Option<Range<u32>>,
    ) -> fmt::Result {
        write!(self.writer, "{piece}")
    }

    fn begin_operand(&mut self) -> fmt::Result {
        Ok(())
    }

    fn end_operand(&mut self) -> fmt::Result {
        Ok(())
    }

    fn finish_instruction(&mut self) -> fmt::Result {
        Ok(())
    }
}

pub(crate) struct InstructionParts<M, O> {
    mnemonic: M,
    operands: O,
}

impl<M, O> InstructionParts<M, O> {
    pub(crate) fn new(mnemonic: M, operands: O) -> Self {
        Self { mnemonic, operands }
    }
}

impl<M: fmt::Write, O: fmt::Write> InstructionWriter for InstructionParts<M, O> {
    fn write_mnemonic_piece(&mut self, piece: OperandPiece) -> fmt::Result {
        write!(self.mnemonic, "{piece}")
    }

    fn write_separator(&mut self, separator: &str) -> fmt::Result {
        self.operands.write_str(separator)
    }

    fn write_operand_piece(
        &mut self,
        piece: OperandPiece,
        _bits: Option<Range<u32>>,
    ) -> fmt::Result {
        write!(self.operands, "{piece}")
    }

    fn begin_operand(&mut self) -> fmt::Result {
        Ok(())
    }

    fn end_operand(&mut self) -> fmt::Result {
        Ok(())
    }

    fn finish_instruction(&mut self) -> fmt::Result {
        Ok(())
    }
}
