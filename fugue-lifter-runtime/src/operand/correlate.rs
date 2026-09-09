use std::ops::Range;

use crate::language::Language;
use crate::operand::operands::{OperandAccess, OperandInfo, OperandKind, OperandPiece, Operands};
use crate::pcode::{Op, PCodeOp, Varnode};

#[derive(Debug, Clone, Default)]
pub struct OperandsContext {
    operations: Vec<PCodeOp>,
    sources: Vec<SourceEntry>,
    register_pool: Vec<Varnode>,
    direct_targets: Vec<u64>,
    indirect_targets: Vec<Varnode>,
    load_addresses: Vec<Varnode>,
    store_addresses: Vec<Varnode>,
    indirect_registers: Vec<Varnode>,
    load_sources: Vec<Varnode>,
    store_sources: Vec<Varnode>,
    read_addresses: Vec<u64>,
    write_addresses: Vec<u64>,
    registers: Vec<Varnode>,
    indirect_memory: bool,
}

#[derive(Debug, Clone)]
struct SourceEntry {
    value: Varnode,
    registers: Range<usize>,
}

impl OperandsContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn operations_mut(&mut self) -> &mut Vec<PCodeOp> {
        &mut self.operations
    }

    fn reset(&mut self) {
        self.sources.clear();
        self.register_pool.clear();
        self.direct_targets.clear();
        self.indirect_targets.clear();
        self.load_addresses.clear();
        self.store_addresses.clear();
        self.indirect_registers.clear();
        self.load_sources.clear();
        self.store_sources.clear();
        self.read_addresses.clear();
        self.write_addresses.clear();
        self.registers.clear();
        self.indirect_memory = false;
    }

    fn analyse(&mut self, register_space: u8, default_space: u8) {
        for index in 0..self.operations.len() {
            let op = self.operations[index];

            let flow_destination = matches!(
                op.op(),
                Op::Branch | Op::CBranch | Op::Call | Op::IBranch | Op::ICall | Op::Return
            );
            for (position, input) in op.inputs().iter().enumerate() {
                if input.space() == default_space && !(flow_destination && position == 0) {
                    self.read_addresses.push(input.offset());
                }
            }

            match op.op() {
                Op::Branch | Op::CBranch | Op::Call => {
                    if let Some(dest) = op.inputs().first()
                        && dest.space() == default_space
                    {
                        self.direct_targets.push(dest.offset());
                    }
                }
                Op::IBranch | Op::ICall => {
                    if let Some(dest) = op.inputs().first() {
                        self.indirect_targets.push(*dest);
                    }
                }
                Op::Load(space) => {
                    if let Some(address) = op.inputs().first() {
                        if address.is_constant() && space == default_space {
                            self.read_addresses.push(address.offset());
                        }
                        self.load_addresses.push(*address);
                    }
                }
                Op::Store(space) => {
                    if let Some(address) = op.inputs().first() {
                        if address.is_constant() && space == default_space {
                            self.write_addresses.push(address.offset());
                        }
                        self.store_addresses.push(*address);
                    }
                }
                _ => {}
            }

            if let Some(output) = op.output() {
                if output.space() == default_space {
                    self.write_addresses.push(output.offset());
                }
                if output.space() != register_space && !output.is_constant() {
                    let start = self.register_pool.len();
                    if !matches!(op.op(), Op::Load(_)) {
                        for input in op.inputs() {
                            Self::append_sources(
                                register_space,
                                &self.sources,
                                &mut self.register_pool,
                                input,
                            );
                        }
                    }
                    self.sources.push(SourceEntry {
                        value: *output,
                        registers: start..self.register_pool.len(),
                    });
                }
            }
        }

        for index in 0..self.indirect_targets.len() {
            let target = self.indirect_targets[index];
            let mark = self.indirect_registers.len();
            Self::resolve_sources(
                register_space,
                &self.sources,
                &self.register_pool,
                &target,
                &mut self.indirect_registers,
            );
            if self.indirect_registers.len() == mark {
                self.indirect_memory = true;
            }
        }

        for index in 0..self.load_addresses.len() {
            let address = self.load_addresses[index];
            Self::resolve_sources(
                register_space,
                &self.sources,
                &self.register_pool,
                &address,
                &mut self.load_sources,
            );
        }

        for index in 0..self.store_addresses.len() {
            let address = self.store_addresses[index];
            Self::resolve_sources(
                register_space,
                &self.sources,
                &self.register_pool,
                &address,
                &mut self.store_sources,
            );
        }
    }

    fn append_sources(
        register_space: u8,
        sources: &[SourceEntry],
        pool: &mut Vec<Varnode>,
        varnode: &Varnode,
    ) {
        if varnode.space() == register_space {
            pool.push(*varnode);
        } else if let Some(registers) = Self::source_registers(sources, varnode) {
            pool.extend_from_within(registers);
        }
    }

    fn resolve_sources(
        register_space: u8,
        sources: &[SourceEntry],
        pool: &[Varnode],
        varnode: &Varnode,
        resolved: &mut Vec<Varnode>,
    ) {
        if varnode.space() == register_space {
            resolved.push(*varnode);
        } else if let Some(registers) = Self::source_registers(sources, varnode) {
            resolved.extend_from_slice(&pool[registers]);
        }
    }

    fn source_registers(sources: &[SourceEntry], varnode: &Varnode) -> Option<Range<usize>> {
        sources
            .iter()
            .rev()
            .find(|entry| entry.value == *varnode)
            .map(|entry| entry.registers.clone())
    }
}

impl Operands {
    pub(crate) fn correlate(&mut self, language: &'static Language, context: &mut OperandsContext) {
        context.reset();
        context.analyse(language.register_space(), language.default_space());

        let facts = FlowFacts {
            ops: &context.operations,
            direct_targets: &context.direct_targets,
            indirect_registers: &context.indirect_registers,
            indirect_memory: context.indirect_memory,
            load_sources: &context.load_sources,
            store_sources: &context.store_sources,
            read_addresses: &context.read_addresses,
            write_addresses: &context.write_addresses,
            has_load: !context.load_addresses.is_empty(),
            has_store: !context.store_addresses.is_empty(),
        };

        let (pieces, operands) = self.parts_mut();
        for operand in operands.iter_mut() {
            operand.apply_flow(&facts, pieces, &mut context.registers);
        }
    }
}

impl OperandInfo {
    fn apply_flow(
        &mut self,
        facts: &FlowFacts<'_>,
        pieces: &mut Vec<OperandPiece>,
        registers: &mut Vec<Varnode>,
    ) {
        registers.clear();
        for piece in &pieces[self.pieces()] {
            if let OperandPiece::Register(register) = piece {
                registers.push(register.varnode());
            }
        }

        match self.kind() {
            OperandKind::Register => {
                for register in registers.iter() {
                    self.insert_access(facts.register_access(register));
                }
                if facts.targets_indirect_register(registers) {
                    self.insert_access(OperandAccess::INDIRECT);
                }
            }
            OperandKind::Scalar => {
                if let Some(value) = self.single_value(pieces)
                    && facts.direct_targets.contains(&value)
                {
                    self.set_code_address(pieces, value);
                    return;
                }
                if let Some(value) = self.memory_value(pieces)
                    && facts.accesses_memory(value)
                {
                    self.set_kind(OperandKind::DataAddress);
                    self.apply_memory_value(value, facts);
                    return;
                }
                self.insert_access(OperandAccess::READ);
            }
            OperandKind::DataAddress => {
                if let Some(value) = self.single_value(pieces)
                    && facts.direct_targets.contains(&value)
                {
                    self.set_code_address(pieces, value);
                    return;
                }
                if let Some(value) = self
                    .single_value(pieces)
                    .or_else(|| self.memory_value(pieces))
                    && facts.accesses_memory(value)
                {
                    self.apply_memory_value(value, facts);
                    return;
                }
                self.apply_memory(registers, facts);
            }
            OperandKind::Dynamic => {
                self.apply_memory(registers, facts);
                if facts.indirect_memory || facts.targets_indirect_register(registers) {
                    self.insert_access(OperandAccess::INDIRECT);
                }
            }
            OperandKind::CodeAddress => {}
        }
    }

    fn single_value(&self, pieces: &[OperandPiece]) -> Option<u64> {
        match &pieces[self.pieces()] {
            [OperandPiece::Scalar(scalar)] => Some(scalar.value() as u64),
            [OperandPiece::Address(offset)] => Some(*offset),
            _ => None,
        }
    }

    fn memory_value(&self, pieces: &[OperandPiece]) -> Option<u64> {
        let pieces = &pieces[self.pieces()];
        if pieces.len() < 2 {
            return None;
        }
        let mut value = None;
        for piece in pieces {
            match piece {
                OperandPiece::Text(_) => {}
                OperandPiece::Register(_) => return None,
                OperandPiece::Scalar(scalar) => {
                    if value.replace(scalar.value() as u64).is_some() {
                        return None;
                    }
                }
                OperandPiece::Address(offset) => {
                    if value.replace(*offset).is_some() {
                        return None;
                    }
                }
            }
        }
        value
    }

    fn set_code_address(&mut self, pieces: &mut Vec<OperandPiece>, target: u64) {
        let start = pieces.len();
        pieces.push(OperandPiece::Address(target));
        self.set_pieces(start..pieces.len());
        self.set_kind(OperandKind::CodeAddress);
    }

    fn apply_memory(&mut self, registers: &[Varnode], facts: &FlowFacts<'_>) {
        if facts.reads_memory(registers) {
            self.insert_access(OperandAccess::READ);
        }
        if facts.writes_memory(registers) {
            self.insert_access(OperandAccess::WRITE);
        }
    }

    fn apply_memory_value(&mut self, value: u64, facts: &FlowFacts<'_>) {
        if facts.read_addresses.contains(&value) {
            self.insert_access(OperandAccess::READ);
        }
        if facts.write_addresses.contains(&value) {
            self.insert_access(OperandAccess::WRITE);
        }
        if facts.indirect_memory {
            self.insert_access(OperandAccess::INDIRECT);
        }
    }
}

struct FlowFacts<'a> {
    ops: &'a [PCodeOp],
    direct_targets: &'a [u64],
    indirect_registers: &'a [Varnode],
    indirect_memory: bool,
    load_sources: &'a [Varnode],
    store_sources: &'a [Varnode],
    read_addresses: &'a [u64],
    write_addresses: &'a [u64],
    has_load: bool,
    has_store: bool,
}

impl FlowFacts<'_> {
    fn register_access(&self, register: &Varnode) -> OperandAccess {
        let mut access = OperandAccess::empty();
        let mut written = false;

        for op in self.ops {
            if !written && op.inputs().iter().any(|input| register.overlaps(input)) {
                access.insert(OperandAccess::READ);
            }
            if let Some(output) = op.output()
                && register.overlaps(output)
            {
                access.insert(OperandAccess::WRITE);
                written = true;
            }
        }

        access
    }

    fn accesses_memory(&self, value: u64) -> bool {
        self.read_addresses.contains(&value) || self.write_addresses.contains(&value)
    }

    fn targets_indirect_register(&self, registers: &[Varnode]) -> bool {
        registers.iter().any(|register| {
            self.indirect_registers
                .iter()
                .any(|target| register.overlaps(target))
        })
    }

    fn reads_memory(&self, registers: &[Varnode]) -> bool {
        if registers.is_empty() {
            self.has_load
        } else {
            registers.iter().any(|register| {
                self.load_sources
                    .iter()
                    .any(|source| register.overlaps(source))
            })
        }
    }

    fn writes_memory(&self, registers: &[Varnode]) -> bool {
        if registers.is_empty() {
            self.has_store
        } else {
            registers.iter().any(|register| {
                self.store_sources
                    .iter()
                    .any(|source| register.overlaps(source))
            })
        }
    }
}
