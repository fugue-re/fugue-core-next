use fugue_lifter::runtime::convention::{Prototype, PrototypeEntry, PrototypeOperand};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

use crate::il::common::{
    IlArtefact, IlBlockId, IlDominance, IlError, IlOpId, IlValueId, RegisterId,
};
use crate::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOpcode};
use crate::il::pcode::RegisterBank;
use crate::lifter::Varnode;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MCodeStorageLocation {
    Register(RegisterId),
    RegisterPair { high: RegisterId, low: RegisterId },
    Stack { offset: i64 },
}

impl MCodeStorageLocation {
    fn from_operand(
        operand: &PrototypeOperand,
        address_bits: u32,
        root_of: &impl Fn(&Varnode) -> Result<RegisterId, IlError>,
    ) -> Result<Self, IlError> {
        match operand {
            PrototypeOperand::Register(varnode) => Ok(Self::Register(root_of(varnode)?)),
            PrototypeOperand::RegisterJoin(high, low) => Ok(Self::RegisterPair {
                high: root_of(high)?,
                low: root_of(low)?,
            }),
            PrototypeOperand::StackRelative(offset) => Ok(Self::Stack {
                offset: Self::normalise_stack_offset(*offset, address_bits)?,
            }),
        }
    }

    fn normalise_stack_offset(offset: u64, address_bits: u32) -> Result<i64, IlError> {
        let shift = 64u32
            .checked_sub(address_bits)
            .filter(|_| address_bits != 0)
            .ok_or_else(|| IlError::integer_overflow("stack offset address width"))?;
        Ok(i64::from_ne_bytes((offset << shift).to_ne_bytes()) >> shift)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct MCodeCallingConventionEntry {
    location: MCodeStorageLocation,
    min_size: usize,
    max_size: usize,
}

impl MCodeCallingConventionEntry {
    const fn new(location: MCodeStorageLocation, min_size: usize, max_size: usize) -> Self {
        Self {
            location,
            min_size,
            max_size,
        }
    }

    pub(crate) const fn location(&self) -> MCodeStorageLocation {
        self.location
    }

    fn accepts_width(&self, width: u32) -> bool {
        let bytes = width.div_ceil(8) as usize;
        self.min_size <= bytes && bytes <= self.max_size
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MCodeCallingConvention {
    inputs: Vec<MCodeCallingConventionEntry>,
    outputs: Vec<MCodeCallingConventionEntry>,
}

impl MCodeCallingConvention {
    pub(crate) fn new(
        inputs: Vec<MCodeCallingConventionEntry>,
        outputs: Vec<MCodeCallingConventionEntry>,
    ) -> Self {
        Self { inputs, outputs }
    }

    pub(crate) fn from_prototype(
        prototype: &Prototype,
        address_bits: u32,
        root_of: impl Fn(&Varnode) -> Result<RegisterId, IlError>,
    ) -> Result<Self, IlError> {
        let build = |entry: &PrototypeEntry| {
            MCodeStorageLocation::from_operand(entry.operand(), address_bits, &root_of).map(
                |location| {
                    MCodeCallingConventionEntry::new(location, entry.min_size(), entry.max_size())
                },
            )
        };
        let inputs = prototype
            .inputs()
            .iter()
            .filter(|entry| entry.meta_type() != Some("float"))
            .map(build)
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = prototype
            .outputs()
            .iter()
            .filter(|entry| entry.meta_type() != Some("float"))
            .map(build)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::new(inputs, outputs))
    }

    pub(crate) fn inputs(&self) -> &[MCodeCallingConventionEntry] {
        &self.inputs
    }

    pub(crate) fn outputs(&self) -> &[MCodeCallingConventionEntry] {
        &self.outputs
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MCodeFunctionFacts {
    return_live_outputs: Vec<MCodeStorageLocation>,
    tail_call_live_outputs: Vec<MCodeStorageLocation>,
}

impl MCodeFunctionFacts {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_return_live_output(&mut self, output: MCodeStorageLocation) {
        if let Err(index) = self.return_live_outputs.binary_search(&output) {
            self.return_live_outputs.insert(index, output);
        }
    }

    pub(crate) fn add_tail_call_live_output(&mut self, output: MCodeStorageLocation) {
        if let Err(index) = self.tail_call_live_outputs.binary_search(&output) {
            self.tail_call_live_outputs.insert(index, output);
        }
    }

    pub(crate) fn return_live_outputs(&self) -> &[MCodeStorageLocation] {
        &self.return_live_outputs
    }

    pub(crate) fn tail_call_live_outputs(&self) -> &[MCodeStorageLocation] {
        &self.tail_call_live_outputs
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MCodeCallFacts {
    inputs: FxHashMap<IlOpId, Vec<MCodeStorageFact>>,
    outputs: FxHashMap<IlOpId, Vec<MCodeStorageFact>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MCodeStorageFact {
    location: MCodeStorageLocation,
    width: u32,
}

impl MCodeStorageFact {
    pub(crate) const fn new(location: MCodeStorageLocation, width: u32) -> Self {
        Self { location, width }
    }

    pub(crate) const fn location(&self) -> MCodeStorageLocation {
        self.location
    }

    pub(crate) const fn width(&self) -> u32 {
        self.width
    }
}

impl MCodeCallFacts {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_input(&mut self, site: IlOpId, input: MCodeStorageFact) {
        Self::insert(&mut self.inputs, site, input);
    }

    pub(crate) fn add_output(&mut self, site: IlOpId, output: MCodeStorageFact) {
        Self::insert(&mut self.outputs, site, output);
    }

    pub(crate) fn inputs(&self, site: IlOpId) -> Option<&[MCodeStorageFact]> {
        self.inputs.get(&site).map(Vec::as_slice)
    }

    pub(crate) fn outputs(&self, site: IlOpId) -> Option<&[MCodeStorageFact]> {
        self.outputs.get(&site).map(Vec::as_slice)
    }

    pub(crate) fn stack_storage(&self) -> impl Iterator<Item = MCodeStorageFact> + '_ {
        self.inputs
            .values()
            .chain(self.outputs.values())
            .flatten()
            .copied()
            .filter(|fact| matches!(fact.location(), MCodeStorageLocation::Stack { .. }))
    }

    fn insert(
        facts: &mut FxHashMap<IlOpId, Vec<MCodeStorageFact>>,
        site: IlOpId,
        fact: MCodeStorageFact,
    ) {
        let values = facts.entry(site).or_default();
        if let Err(index) = values.binary_search(&fact) {
            values.insert(index, fact);
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MCodeCallArgument {
    Pair { high: IlValueId, low: IlValueId },
    Stack { offset: i64, width: u32 },
    Value(IlValueId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MCodeCallOutput {
    location: MCodeStorageLocation,
    components: SmallVec<[MCodeCallOutputComponent; 2]>,
}

impl MCodeCallOutput {
    fn new(
        location: MCodeStorageLocation,
        components: impl IntoIterator<Item = MCodeCallOutputComponent>,
    ) -> Self {
        Self {
            location,
            components: components.into_iter().collect(),
        }
    }

    pub(crate) const fn location(&self) -> MCodeStorageLocation {
        self.location
    }

    pub(crate) fn components(&self) -> &[MCodeCallOutputComponent] {
        &self.components
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MCodeCallOutputComponent {
    Register { register: RegisterId, width: u32 },
    Stack { offset: i64, width: u32 },
}

impl MCodeCallOutputComponent {
    const fn register(register: RegisterId, width: u32) -> Self {
        Self::Register { register, width }
    }

    const fn stack(offset: i64, width: u32) -> Self {
        Self::Stack { offset, width }
    }

    pub(crate) const fn register_id(&self) -> Option<RegisterId> {
        match *self {
            Self::Register { register, .. } => Some(register),
            Self::Stack { .. } => None,
        }
    }

    pub(crate) const fn stack_offset(&self) -> Option<i64> {
        match *self {
            Self::Register { .. } => None,
            Self::Stack { offset, .. } => Some(offset),
        }
    }

    pub(crate) const fn width(&self) -> u32 {
        match *self {
            Self::Register { width, .. } | Self::Stack { width, .. } => width,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MCodeCall {
    arguments: Vec<MCodeCallArgument>,
    outputs: Vec<MCodeCallOutput>,
    tail_call: bool,
}

impl MCodeCall {
    pub(crate) fn arguments(&self) -> &[MCodeCallArgument] {
        &self.arguments
    }

    pub(crate) fn outputs(&self) -> &[MCodeCallOutput] {
        &self.outputs
    }

    pub(crate) const fn is_tail_call(&self) -> bool {
        self.tail_call
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MCodeAbiModel {
    calls: FxHashMap<IlOpId, MCodeCall>,
    exit_values: FxHashMap<IlOpId, Vec<IlValueId>>,
}

impl MCodeAbiModel {
    pub(crate) fn new(
        ir: &ECodeSsaIr,
        convention: &MCodeCallingConvention,
        function: &MCodeFunctionFacts,
        calls: &MCodeCallFacts,
        registers: &RegisterBank,
    ) -> Result<Self, IlError> {
        let dominance = ir.analyse::<IlDominance>();
        let entry_live_inputs = Self::entry_live_inputs(ir);
        let mut model = Self::default();
        if ir.graph().blocks().is_empty() {
            for (index, operation) in ir.operations().iter().enumerate() {
                let site = IlOpId::try_from_index(index).expect("operation id is representable");
                match operation.opcode() {
                    ECodeSsaOpcode::Call | ECodeSsaOpcode::CallIndirect => {
                        let reaching = |root| {
                            Self::reaching_linear_register_value(ir, site, root).filter(|&value| {
                                Self::is_reaching_input(ir, &entry_live_inputs, value)
                            })
                        };
                        let inputs = Self::call_input_locations(convention, calls.inputs(site));
                        let outputs =
                            Self::recover_call_outputs(convention, calls.outputs(site), registers)?;
                        model
                            .calls
                            .insert(site, Self::recover_call(&inputs, reaching, outputs, false));
                    }
                    ECodeSsaOpcode::Return => {
                        model.exit_values.insert(
                            site,
                            Self::reaching_linear_locations(
                                ir,
                                site,
                                function.return_live_outputs(),
                            ),
                        );
                    }
                    _ => {}
                }
            }
            return Ok(model);
        }

        for block_index in 0..ir.graph().blocks().len() {
            let block = IlBlockId::try_from_index(block_index).expect("block id is representable");
            let block_record = ir.graph().blocks()[block_index];
            for (site, operation) in ir.operations_for_block(block) {
                let tail_call = block_record.is_exit()
                    && block_record.successors().is_empty()
                    && matches!(
                        operation.opcode(),
                        ECodeSsaOpcode::Branch | ECodeSsaOpcode::BranchIndirect
                    );
                if tail_call
                    || matches!(
                        operation.opcode(),
                        ECodeSsaOpcode::Call | ECodeSsaOpcode::CallIndirect
                    )
                {
                    let reaching = |root| {
                        Self::reaching_register_value(ir, &dominance, block, site, root)
                            .filter(|&value| Self::is_reaching_input(ir, &entry_live_inputs, value))
                    };
                    let inputs = Self::call_input_locations(convention, calls.inputs(site));
                    let outputs = if tail_call {
                        Vec::new()
                    } else {
                        Self::recover_call_outputs(convention, calls.outputs(site), registers)?
                    };
                    model.calls.insert(
                        site,
                        Self::recover_call(&inputs, reaching, outputs, tail_call),
                    );
                }

                let exit_registers = if tail_call {
                    Some(function.tail_call_live_outputs())
                } else if operation.opcode() == ECodeSsaOpcode::Return {
                    Some(function.return_live_outputs())
                } else {
                    None
                };
                if let Some(exit_registers) = exit_registers {
                    model.exit_values.insert(
                        site,
                        Self::reaching_location_values(ir, &dominance, block, site, exit_registers),
                    );
                }
            }
        }

        Ok(model)
    }

    pub(crate) fn call(&self, site: IlOpId) -> Option<&MCodeCall> {
        self.calls.get(&site)
    }

    pub(crate) fn exit_values(&self, site: IlOpId) -> &[IlValueId] {
        self.exit_values.get(&site).map_or(&[], Vec::as_slice)
    }

    fn entry_live_inputs(ir: &ECodeSsaIr) -> FxHashSet<IlValueId> {
        let mut entry_live_inputs = FxHashSet::default();
        let mut seen = FxHashSet::default();
        for index in 0..ir.values().len() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let Some(domain) = ir
                .value_domain(value)
                .filter(ECodeSsaDomain::is_register_or_flag)
            else {
                continue;
            };
            if seen.insert(domain)
                && ir
                    .defining_operation(value)
                    .is_some_and(|operation| operation.opcode() == ECodeSsaOpcode::Undefined)
            {
                entry_live_inputs.insert(value);
            }
        }
        entry_live_inputs
    }

    fn is_reaching_input(
        ir: &ECodeSsaIr,
        entry_live_inputs: &FxHashSet<IlValueId>,
        value: IlValueId,
    ) -> bool {
        ir.defining_operation(value).is_none_or(|operation| {
            operation.opcode() != ECodeSsaOpcode::Undefined || entry_live_inputs.contains(&value)
        })
    }

    fn recover_call(
        inputs: &[MCodeStorageFact],
        mut reaching: impl FnMut(RegisterId) -> Option<IlValueId>,
        outputs: Vec<MCodeCallOutput>,
        tail_call: bool,
    ) -> MCodeCall {
        let mut arguments = Vec::new();
        for &input in inputs {
            match input.location() {
                MCodeStorageLocation::Register(root) => match reaching(root) {
                    Some(value) => arguments.push(MCodeCallArgument::Value(value)),
                    None => break,
                },
                MCodeStorageLocation::RegisterPair { high, low } => {
                    match (reaching(high), reaching(low)) {
                        (Some(high), Some(low)) => {
                            arguments.push(MCodeCallArgument::Pair { high, low })
                        }
                        _ => break,
                    }
                }
                MCodeStorageLocation::Stack { offset } => {
                    arguments.push(MCodeCallArgument::Stack {
                        offset,
                        width: input.width(),
                    })
                }
            }
        }
        MCodeCall {
            arguments,
            outputs,
            tail_call,
        }
    }

    fn call_input_locations(
        convention: &MCodeCallingConvention,
        facts: Option<&[MCodeStorageFact]>,
    ) -> SmallVec<[MCodeStorageFact; 8]> {
        facts.map_or_else(
            || {
                convention
                    .inputs()
                    .iter()
                    .take_while(|entry| {
                        !matches!(entry.location(), MCodeStorageLocation::Stack { .. })
                    })
                    .map(|entry| {
                        MCodeStorageFact::new(
                            entry.location(),
                            u32::try_from(entry.max_size)
                                .ok()
                                .and_then(|bytes| bytes.checked_mul(8))
                                .unwrap_or(0),
                        )
                    })
                    .collect()
            },
            |facts| facts.iter().copied().collect(),
        )
    }

    fn recover_call_outputs(
        convention: &MCodeCallingConvention,
        facts: Option<&[MCodeStorageFact]>,
        registers: &RegisterBank,
    ) -> Result<Vec<MCodeCallOutput>, IlError> {
        let entries = match facts {
            Some(facts) => facts
                .iter()
                .map(|fact| {
                    (
                        MCodeCallingConventionEntry::new(
                            fact.location(),
                            fact.width().div_ceil(8) as usize,
                            fact.width().div_ceil(8) as usize,
                        ),
                        Some(fact.width()),
                    )
                })
                .collect::<Vec<_>>(),
            None => convention
                .outputs()
                .iter()
                .copied()
                .take_while(|entry| !matches!(entry.location(), MCodeStorageLocation::Stack { .. }))
                .map(|entry| (entry, None))
                .collect(),
        };
        entries
            .into_iter()
            .filter_map(|(entry, exact_width)| match entry.location() {
                MCodeStorageLocation::Register(register) => Some(
                    registers
                        .root_bits(register)
                        .filter(|width| {
                            exact_width.map_or_else(
                                || entry.accepts_width(*width),
                                |expected| expected == *width,
                            )
                        })
                        .map(|width| {
                            MCodeCallOutput::new(
                                entry.location(),
                                [MCodeCallOutputComponent::register(register, width)],
                            )
                        })
                        .ok_or_else(|| {
                            IlError::missing_component(ECodeSsaIr::FORM, "call output width")
                        }),
                ),
                MCodeStorageLocation::RegisterPair { high, low } => Some(
                    registers
                        .root_bits(high)
                        .zip(registers.root_bits(low))
                        .filter(|(high_width, low_width)| {
                            high_width
                                .checked_add(*low_width)
                                .is_some_and(|width| entry.accepts_width(width))
                        })
                        .map(|(high_width, low_width)| {
                            MCodeCallOutput::new(
                                entry.location(),
                                [
                                    MCodeCallOutputComponent::register(high, high_width),
                                    MCodeCallOutputComponent::register(low, low_width),
                                ],
                            )
                        })
                        .ok_or_else(|| {
                            IlError::missing_component(ECodeSsaIr::FORM, "call output width")
                        }),
                ),
                MCodeStorageLocation::Stack { offset } => exact_width.map(|width| {
                    Ok(MCodeCallOutput::new(
                        entry.location(),
                        [MCodeCallOutputComponent::stack(offset, width)],
                    ))
                }),
            })
            .collect()
    }

    fn reaching_register_value(
        ir: &ECodeSsaIr,
        dominance: &IlDominance,
        mut block: IlBlockId,
        site: IlOpId,
        root: RegisterId,
    ) -> Option<IlValueId> {
        let domain = ECodeSsaDomain::Register(root);
        let mut operation_limit = Some(site);

        loop {
            for (candidate, operation) in ir.operations_for_block(block).rev() {
                if operation_limit.is_some_and(|limit| candidate.index() >= limit.index()) {
                    continue;
                }
                if operation.results().is_empty() {
                    continue;
                }
                let result = IlValueId::try_from_index(operation.results().start())
                    .expect("value id is representable");
                if ir.value_domain(result) == Some(domain) {
                    return Some(result);
                }
            }

            for argument in ir.block_arguments() {
                if argument.block() == block && ir.value_domain(argument.value()) == Some(domain) {
                    return Some(argument.value());
                }
            }

            block = dominance.immediate_dominator(block)?;
            operation_limit = None;
        }
    }

    fn reaching_linear_locations(
        ir: &ECodeSsaIr,
        site: IlOpId,
        locations: &[MCodeStorageLocation],
    ) -> Vec<IlValueId> {
        locations
            .iter()
            .flat_map(|location| match *location {
                MCodeStorageLocation::Register(root) => [Some(root), None],
                MCodeStorageLocation::RegisterPair { high, low } => [Some(high), Some(low)],
                MCodeStorageLocation::Stack { .. } => [None, None],
            })
            .flatten()
            .filter_map(|root| Self::reaching_linear_register_value(ir, site, root))
            .collect()
    }

    fn reaching_location_values(
        ir: &ECodeSsaIr,
        dominance: &IlDominance,
        block: IlBlockId,
        site: IlOpId,
        locations: &[MCodeStorageLocation],
    ) -> Vec<IlValueId> {
        locations
            .iter()
            .flat_map(|location| match *location {
                MCodeStorageLocation::Register(root) => [Some(root), None],
                MCodeStorageLocation::RegisterPair { high, low } => [Some(high), Some(low)],
                MCodeStorageLocation::Stack { .. } => [None, None],
            })
            .flatten()
            .filter_map(|root| Self::reaching_register_value(ir, dominance, block, site, root))
            .collect()
    }

    fn reaching_linear_register_value(
        ir: &ECodeSsaIr,
        site: IlOpId,
        root: RegisterId,
    ) -> Option<IlValueId> {
        let domain = ECodeSsaDomain::Register(root);
        for operation in ir.operations().get(..site.index())?.iter().rev() {
            if operation.results().is_empty() {
                continue;
            }
            let result = IlValueId::try_from_index(operation.results().start()).ok()?;
            if ir.value_domain(result) == Some(domain) {
                return Some(result);
            }
        }
        None
    }
}

#[cfg(test)]
mod test;
