use fugue_lifter::runtime::convention::{Prototype, PrototypeEntry, PrototypeOperand};
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;

use super::stack::{MCodeStackAccess, MCodeStackModel};
use crate::il::common::{
    IlArtefact, IlBlockId, IlCsr, IlDominance, IlDominanceEvent, IlError, IlOpId, IlValueId,
    RegisterBank, RegisterId,
};
use crate::il::ecode::{ECodeDomain, ECodeIr, ECodeOp, ECodeOpcode};
use crate::il::mcode::MCodeStorageLocation;
use crate::ir::FunctionId;
use crate::lifter::Varnode;

fn normalise_stack_offset(offset: u64, address_bits: u32) -> Result<i64, IlError> {
    let shift = 64u32
        .checked_sub(address_bits)
        .filter(|_| address_bits != 0)
        .ok_or_else(|| IlError::integer_overflow("stack offset address width"))?;
    Ok(i64::from_ne_bytes((offset << shift).to_ne_bytes()) >> shift)
}

fn storage_location(
    operand: &PrototypeOperand,
    address_bits: u32,
    root_of: &impl Fn(&Varnode) -> Result<RegisterId, IlError>,
) -> Result<MCodeStorageLocation, IlError> {
    match operand {
        PrototypeOperand::Register(varnode) => {
            Ok(MCodeStorageLocation::Register(root_of(varnode)?))
        }
        PrototypeOperand::RegisterJoin(high, low) => Ok(MCodeStorageLocation::RegisterPair {
            high: root_of(high)?,
            low: root_of(low)?,
        }),
        PrototypeOperand::StackRelative(offset) => Ok(MCodeStorageLocation::Stack {
            offset: normalise_stack_offset(*offset, address_bits)?,
        }),
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct MCodeCallingConventionEntry {
    location: MCodeStorageLocation,
    min_bytes: usize,
    max_bytes: usize,
}

impl MCodeCallingConventionEntry {
    const fn new(location: MCodeStorageLocation, min_bytes: usize, max_bytes: usize) -> Self {
        Self {
            location,
            min_bytes,
            max_bytes,
        }
    }

    pub(crate) const fn location(&self) -> MCodeStorageLocation {
        self.location
    }

    fn accepts_width(&self, width: u32) -> bool {
        let bytes = width.div_ceil(8) as usize;
        self.min_bytes <= bytes && bytes <= self.max_bytes
    }

    pub(crate) fn resolve_fact(
        &self,
        registers: &RegisterBank,
    ) -> Result<Option<MCodeStorageFact>, IlError> {
        if matches!(self.location, MCodeStorageLocation::Stack { .. }) {
            return Ok(None);
        }
        let width = self.location.register_width(registers).ok_or_else(|| {
            IlError::missing_component(ECodeIr::FORM, "calling-convention register width")
        })?;
        if !self.accepts_width(width) {
            return Err(IlError::width_mismatch(ECodeIr::FORM));
        }
        Ok(Some(MCodeStorageFact::new(self.location, width)))
    }
}

#[derive(Debug, Default)]
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
            storage_location(entry.operand(), address_bits, &root_of).map(|location| {
                MCodeCallingConventionEntry::new(location, entry.min_size(), entry.max_size())
            })
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MCodeStorageFact {
    location: MCodeStorageLocation,
    width: u32,
}

impl MCodeStorageFact {
    pub const fn new(location: MCodeStorageLocation, width: u32) -> Self {
        Self { location, width }
    }

    pub const fn location(&self) -> MCodeStorageLocation {
        self.location
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    fn validate(&self, registers: &RegisterBank) -> Result<(), IlError> {
        if self.width == 0 {
            return Err(IlError::width_mismatch(ECodeIr::FORM));
        }

        match self.location {
            MCodeStorageLocation::Register(_) | MCodeStorageLocation::RegisterPair { .. } => {
                let width = self.location.register_width(registers).ok_or_else(|| {
                    IlError::missing_component(ECodeIr::FORM, "storage fact register root")
                })?;
                if self.width != width {
                    return Err(IlError::width_mismatch(ECodeIr::FORM));
                }
            }
            MCodeStorageLocation::Stack { offset } => {
                offset
                    .checked_add(i64::from(self.width.div_ceil(8)))
                    .ok_or_else(|| IlError::integer_overflow("stack storage range"))?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MCodeCallFacts {
    site: IlOpId,
    inputs: Option<Vec<MCodeStorageFact>>,
    outputs: Option<Vec<MCodeStorageFact>>,
}

impl MCodeCallFacts {
    pub fn new(site: IlOpId) -> Self {
        Self {
            site,
            inputs: None,
            outputs: None,
        }
    }

    pub const fn site(&self) -> IlOpId {
        self.site
    }

    pub fn inputs(&self) -> Option<&[MCodeStorageFact]> {
        self.inputs.as_deref()
    }

    pub fn outputs(&self) -> Option<&[MCodeStorageFact]> {
        self.outputs.as_deref()
    }

    fn stack_storage(&self) -> impl Iterator<Item = MCodeStorageFact> + '_ {
        self.inputs
            .iter()
            .chain(&self.outputs)
            .flat_map(|facts| facts.iter().copied())
            .filter(|fact| matches!(fact.location(), MCodeStorageLocation::Stack { .. }))
    }

    pub fn set_inputs(&mut self, inputs: impl IntoIterator<Item = MCodeStorageFact>) {
        self.inputs = Some(inputs.into_iter().collect());
    }

    pub fn set_outputs(&mut self, outputs: impl IntoIterator<Item = MCodeStorageFact>) {
        self.outputs = Some(outputs.into_iter().collect());
    }

    pub fn insert_input(&mut self, input: MCodeStorageFact) {
        self.inputs.get_or_insert_with(Vec::new).push(input);
    }

    pub fn insert_output(&mut self, output: MCodeStorageFact) {
        self.outputs.get_or_insert_with(Vec::new).push(output);
    }

    fn validate(&self, ir: &ECodeIr, registers: &RegisterBank) -> Result<(), IlError> {
        let operation = ir
            .ops()
            .get(self.site.index())
            .ok_or_else(|| IlError::range_out_of_bounds(self.site.index() + 1, ir.ops().len()))?;
        let is_tail_call = matches!(
            operation.opcode(),
            ECodeOpcode::Branch | ECodeOpcode::BranchIndirect
        ) && ir
            .block_for_op(self.site)
            .and_then(|block| ir.graph().blocks().get(block.index()))
            .is_some_and(|block| {
                block.is_exit()
                    && block.successors().is_empty()
                    && block.ops().end() == self.site.index() + 1
            });
        if !is_tail_call
            && !matches!(
                operation.opcode(),
                ECodeOpcode::Call | ECodeOpcode::CallIndirect
            )
        {
            return Err(IlError::invalid_fact_site(self.site.value()));
        }

        for fact in self
            .inputs
            .iter()
            .chain(&self.outputs)
            .flat_map(|facts| facts.iter())
        {
            fact.validate(registers)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MCodeFunctionFacts {
    function: FunctionId,
    return_live_outputs: Option<Vec<MCodeStorageFact>>,
    tail_call_live_outputs: Option<Vec<MCodeStorageFact>>,
    calls: FxHashMap<IlOpId, MCodeCallFacts>,
}

impl MCodeFunctionFacts {
    pub fn new(function: FunctionId) -> Self {
        Self {
            function,
            return_live_outputs: None,
            tail_call_live_outputs: None,
            calls: FxHashMap::default(),
        }
    }

    pub const fn function(&self) -> FunctionId {
        self.function
    }

    pub fn return_live_outputs(&self) -> Option<&[MCodeStorageFact]> {
        self.return_live_outputs.as_deref()
    }

    pub fn tail_call_live_outputs(&self) -> Option<&[MCodeStorageFact]> {
        self.tail_call_live_outputs.as_deref()
    }

    pub(crate) fn stack_storage(&self) -> impl Iterator<Item = MCodeStorageFact> + '_ {
        self.calls
            .values()
            .flat_map(MCodeCallFacts::stack_storage)
            .chain(
                self.return_live_outputs
                    .iter()
                    .chain(&self.tail_call_live_outputs)
                    .flat_map(|facts| facts.iter().copied())
                    .filter(|fact| matches!(fact.location(), MCodeStorageLocation::Stack { .. })),
            )
    }

    pub fn set_return_live_outputs(&mut self, outputs: impl IntoIterator<Item = MCodeStorageFact>) {
        let mut outputs = outputs.into_iter().collect::<Vec<_>>();
        outputs.sort_unstable();
        outputs.dedup();
        self.return_live_outputs = Some(outputs);
    }

    pub fn set_tail_call_live_outputs(
        &mut self,
        outputs: impl IntoIterator<Item = MCodeStorageFact>,
    ) {
        let mut outputs = outputs.into_iter().collect::<Vec<_>>();
        outputs.sort_unstable();
        outputs.dedup();
        self.tail_call_live_outputs = Some(outputs);
    }

    pub fn call(&self, site: IlOpId) -> Option<&MCodeCallFacts> {
        self.calls.get(&site)
    }

    pub fn insert_return_live_output(&mut self, output: MCodeStorageFact) {
        let outputs = self.return_live_outputs.get_or_insert_with(Vec::new);
        if let Err(index) = outputs.binary_search(&output) {
            outputs.insert(index, output);
        }
    }

    pub fn insert_tail_call_live_output(&mut self, output: MCodeStorageFact) {
        let outputs = self.tail_call_live_outputs.get_or_insert_with(Vec::new);
        if let Err(index) = outputs.binary_search(&output) {
            outputs.insert(index, output);
        }
    }

    pub fn insert_call(&mut self, call: MCodeCallFacts) -> Option<MCodeCallFacts> {
        self.calls.insert(call.site(), call)
    }

    pub(crate) fn validate(&self, ir: &ECodeIr, registers: &RegisterBank) -> Result<(), IlError> {
        if self.function != ir.metadata().function() {
            return Err(IlError::function_mismatch(
                ir.metadata().function(),
                self.function,
            ));
        }
        for outputs in [&self.return_live_outputs, &self.tail_call_live_outputs]
            .into_iter()
            .flatten()
        {
            if outputs.windows(2).any(|pair| {
                pair[0].location() == pair[1].location() && pair[0].width() != pair[1].width()
            }) {
                return Err(IlError::width_mismatch(ECodeIr::FORM));
            }
            for output in outputs {
                output.validate(registers)?;
            }
        }
        for call in self.calls.values() {
            call.validate(ir, registers)?;
        }
        Ok(())
    }

    pub(crate) fn validate_stack(&self, stack: &MCodeStackModel) -> Result<(), IlError> {
        if self.stack_storage().any(|fact| {
            let MCodeStorageLocation::Stack { offset } = fact.location() else {
                return false;
            };
            stack.storage_access(offset, fact.width()).is_none()
        }) {
            return Err(IlError::missing_component(
                ECodeIr::FORM,
                "stack storage fact",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MCodeCallArg {
    Pair { high: IlValueId, low: IlValueId },
    Stack { offset: i64, width: u32 },
    Value(IlValueId),
}

#[derive(Debug, PartialEq, Eq)]
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
    Register {
        register: RegisterId,
        width: u32,
    },
    Stack {
        access: MCodeStackAccess,
        object_width: u32,
        width: u32,
    },
}

impl MCodeCallOutputComponent {
    const fn register(register: RegisterId, width: u32) -> Self {
        Self::Register { register, width }
    }

    const fn stack(access: MCodeStackAccess, object_width: u32, width: u32) -> Self {
        Self::Stack {
            access,
            object_width,
            width,
        }
    }

    pub(crate) const fn width(&self) -> u32 {
        match *self {
            Self::Register { width, .. } | Self::Stack { width, .. } => width,
        }
    }
}

#[derive(Debug)]
pub(crate) struct MCodeCall {
    args: Vec<MCodeCallArg>,
    outputs: Vec<MCodeCallOutput>,
    tail_call: bool,
}

impl MCodeCall {
    pub(crate) fn args(&self) -> &[MCodeCallArg] {
        &self.args
    }

    pub(crate) fn outputs(&self) -> &[MCodeCallOutput] {
        &self.outputs
    }

    pub(crate) const fn is_tail_call(&self) -> bool {
        self.tail_call
    }
}

#[derive(Debug, Default)]
pub(crate) struct MCodeAbiModel {
    calls: FxHashMap<IlOpId, MCodeCall>,
    exit_requirements: FxHashMap<IlOpId, Vec<MCodeExitRequirement>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MCodeExitRequirement {
    Register(IlValueId),
    Stack(MCodeStackAccess),
}

struct MCodeAbiSolver<'a> {
    ir: &'a ECodeIr,
    convention: &'a MCodeCallingConvention,
    return_live_outputs: &'a [MCodeStorageFact],
    tail_call_live_outputs: &'a [MCodeStorageFact],
    facts: Option<&'a MCodeFunctionFacts>,
    registers: &'a RegisterBank,
    stack: &'a MCodeStackModel,
    entry_live_inputs: FxHashSet<IlValueId>,
    model: MCodeAbiModel,
}

#[derive(Debug, Default)]
struct MCodeReachingDefs {
    values: FxHashMap<RegisterId, IlValueId>,
    undo: Vec<(RegisterId, Option<IlValueId>)>,
    tracking: bool,
}

impl MCodeReachingDefs {
    fn value(&self, register: RegisterId) -> Option<IlValueId> {
        self.values.get(&register).copied()
    }

    fn checkpoint(&mut self) -> usize {
        self.tracking = true;
        self.undo.len()
    }

    fn rollback(&mut self, checkpoint: usize) {
        while self.undo.len() > checkpoint {
            let (register, previous) = self
                .undo
                .pop()
                .expect("a register-definitions checkpoint is within the undo log");
            match previous {
                Some(value) => {
                    self.values.insert(register, value);
                }
                None => {
                    self.values.remove(&register);
                }
            }
        }
    }

    fn define_value(&mut self, ir: &ECodeIr, value: IlValueId) {
        if let Some(ECodeDomain::Register(register)) = ir.value_domain(value) {
            let previous = self.values.insert(register, value);
            if self.tracking {
                self.undo.push((register, previous));
            }
        }
    }

    fn apply_op(&mut self, ir: &ECodeIr, operation: &ECodeOp) {
        for index in operation.results().start()..operation.results().end() {
            self.define_value(
                ir,
                IlValueId::try_from_index(index).expect("value id is representable"),
            );
        }
    }
}

impl MCodeAbiModel {
    pub(crate) fn new(
        ir: &ECodeIr,
        convention: &MCodeCallingConvention,
        return_live_outputs: &[MCodeStorageFact],
        tail_call_live_outputs: &[MCodeStorageFact],
        facts: Option<&MCodeFunctionFacts>,
        registers: &RegisterBank,
        stack: &MCodeStackModel,
    ) -> Result<Self, IlError> {
        MCodeAbiSolver::new(
            ir,
            convention,
            return_live_outputs,
            tail_call_live_outputs,
            facts,
            registers,
            stack,
        )
        .solve()
    }

    pub(crate) fn call(&self, site: IlOpId) -> Option<&MCodeCall> {
        self.calls.get(&site)
    }

    pub(crate) fn exit_requirements(&self, site: IlOpId) -> &[MCodeExitRequirement] {
        self.exit_requirements.get(&site).map_or(&[], Vec::as_slice)
    }
}

impl<'a> MCodeAbiSolver<'a> {
    fn new(
        ir: &'a ECodeIr,
        convention: &'a MCodeCallingConvention,
        return_live_outputs: &'a [MCodeStorageFact],
        tail_call_live_outputs: &'a [MCodeStorageFact],
        facts: Option<&'a MCodeFunctionFacts>,
        registers: &'a RegisterBank,
        stack: &'a MCodeStackModel,
    ) -> Self {
        let mut entry_live_inputs = FxHashSet::default();
        let mut seen = FxHashSet::default();
        for index in 0..ir.values().len() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let Some(domain) = ir
                .value_domain(value)
                .filter(ECodeDomain::is_register_or_flag)
            else {
                continue;
            };
            if seen.insert(domain)
                && ir
                    .defining_op(value)
                    .is_some_and(|operation| operation.opcode() == ECodeOpcode::Undefined)
            {
                entry_live_inputs.insert(value);
            }
        }

        Self {
            ir,
            convention,
            return_live_outputs,
            tail_call_live_outputs,
            facts,
            registers,
            stack,
            entry_live_inputs,
            model: MCodeAbiModel::default(),
        }
    }

    fn is_reaching_input(&self, value: IlValueId) -> bool {
        self.ir.defining_op(value).is_none_or(|operation| {
            operation.opcode() != ECodeOpcode::Undefined || self.entry_live_inputs.contains(&value)
        })
    }

    fn solve(mut self) -> Result<MCodeAbiModel, IlError> {
        if self.ir.graph().blocks().is_empty() {
            let mut definitions = MCodeReachingDefs::default();
            for (index, operation) in self.ir.ops().iter().enumerate() {
                let site = IlOpId::try_from_index(index).expect("operation id is representable");
                self.recover_op(&definitions, site, operation, false)?;
                definitions.apply_op(self.ir, operation);
            }
            return Ok(self.model);
        }

        let dominance = self.ir.analyse::<IlDominance>();
        let block_args = IlCsr::from_entries(
            self.ir.graph().blocks().len(),
            self.ir
                .block_args()
                .iter()
                .map(|arg| (arg.block().index(), arg.value())),
        );
        if let Some(entry) = self.ir.graph().entry_block() {
            let mut definitions = MCodeReachingDefs::default();
            let mut checkpoints = Vec::new();
            for event in dominance.events_from(entry) {
                match event {
                    IlDominanceEvent::Enter(block) => {
                        checkpoints.push(definitions.checkpoint());
                        self.recover_block(block, &block_args, &mut definitions)?;
                    }
                    IlDominanceEvent::Exit(_) => {
                        definitions.rollback(
                            checkpoints
                                .pop()
                                .expect("each dominance exit follows a matching entry"),
                        );
                    }
                }
            }
        }
        for index in 0..self.ir.graph().blocks().len() {
            let block = IlBlockId::try_from_index(index).expect("block id is representable");
            if !dominance.is_reachable(block) {
                let mut definitions = MCodeReachingDefs::default();
                self.recover_block(block, &block_args, &mut definitions)?;
            }
        }

        Ok(self.model)
    }

    fn recover_block(
        &mut self,
        block: IlBlockId,
        block_args: &IlCsr<IlValueId>,
        definitions: &mut MCodeReachingDefs,
    ) -> Result<(), IlError> {
        for &arg in block_args.row(block.index()) {
            definitions.define_value(self.ir, arg);
        }
        let block_record = self.ir.graph().blocks()[block.index()];
        for (site, operation) in self.ir.graph().ops_for_block(block, self.ir.ops()) {
            let tail_call = block_record.is_exit()
                && block_record.successors().is_empty()
                && matches!(
                    operation.opcode(),
                    ECodeOpcode::Branch | ECodeOpcode::BranchIndirect
                );
            self.recover_op(definitions, site, operation, tail_call)?;
            definitions.apply_op(self.ir, operation);
        }
        Ok(())
    }

    fn recover_op(
        &mut self,
        definitions: &MCodeReachingDefs,
        site: IlOpId,
        operation: &ECodeOp,
        tail_call: bool,
    ) -> Result<(), IlError> {
        if tail_call
            || matches!(
                operation.opcode(),
                ECodeOpcode::Call | ECodeOpcode::CallIndirect
            )
        {
            let facts = self.facts.and_then(|facts| facts.call(site));
            let inputs = self.call_input_locations(facts.and_then(MCodeCallFacts::inputs))?;
            let outputs = if tail_call {
                Vec::new()
            } else {
                self.recover_call_outputs(facts.and_then(MCodeCallFacts::outputs))?
            };
            let call = self.recover_call(&inputs, definitions, outputs, tail_call)?;
            self.model.calls.insert(site, call);
        }

        let exit_facts = if tail_call {
            Some(
                self.facts
                    .and_then(MCodeFunctionFacts::tail_call_live_outputs)
                    .unwrap_or(self.tail_call_live_outputs),
            )
        } else if operation.opcode() == ECodeOpcode::Return {
            Some(
                self.facts
                    .and_then(MCodeFunctionFacts::return_live_outputs)
                    .unwrap_or(self.return_live_outputs),
            )
        } else {
            None
        };
        if let Some(exit_facts) = exit_facts {
            let requirements = self.recover_exit_requirements(definitions, exit_facts)?;
            self.model.exit_requirements.insert(site, requirements);
        }

        Ok(())
    }

    fn recover_call(
        &self,
        inputs: &[MCodeStorageFact],
        definitions: &MCodeReachingDefs,
        outputs: Vec<MCodeCallOutput>,
        tail_call: bool,
    ) -> Result<MCodeCall, IlError> {
        let reaching = |register| {
            definitions
                .value(register)
                .filter(|&value| self.is_reaching_input(value))
        };
        let mut args = Vec::new();
        for &input in inputs {
            match input.location() {
                MCodeStorageLocation::Register(root) => match reaching(root) {
                    Some(value) => {
                        if self.ir.value_width(value) != Some(input.width()) {
                            return Err(IlError::width_mismatch(ECodeIr::FORM));
                        }
                        args.push(MCodeCallArg::Value(value));
                    }
                    None => break,
                },
                MCodeStorageLocation::RegisterPair { high, low } => {
                    match (reaching(high), reaching(low)) {
                        (Some(high_value), Some(low_value)) => {
                            let high_width = self.registers.root_bits(high).ok_or_else(|| {
                                IlError::missing_component(ECodeIr::FORM, "call input register")
                            })?;
                            let low_width = self.registers.root_bits(low).ok_or_else(|| {
                                IlError::missing_component(ECodeIr::FORM, "call input register")
                            })?;
                            if self.ir.value_width(high_value) != Some(high_width)
                                || self.ir.value_width(low_value) != Some(low_width)
                            {
                                return Err(IlError::width_mismatch(ECodeIr::FORM));
                            }
                            args.push(MCodeCallArg::Pair {
                                high: high_value,
                                low: low_value,
                            });
                        }
                        _ => break,
                    }
                }
                MCodeStorageLocation::Stack { offset } => args.push(MCodeCallArg::Stack {
                    offset,
                    width: input.width(),
                }),
            }
        }
        Ok(MCodeCall {
            args,
            outputs,
            tail_call,
        })
    }

    fn call_input_locations(
        &self,
        facts: Option<&[MCodeStorageFact]>,
    ) -> Result<SmallVec<[MCodeStorageFact; 8]>, IlError> {
        facts.map_or_else(
            || {
                self.convention
                    .inputs()
                    .iter()
                    .take_while(|entry| {
                        !matches!(entry.location(), MCodeStorageLocation::Stack { .. })
                    })
                    .map(|entry| {
                        entry.resolve_fact(self.registers)?.ok_or_else(|| {
                            IlError::missing_component(ECodeIr::FORM, "calling-convention input")
                        })
                    })
                    .collect()
            },
            |facts| Ok(facts.iter().copied().collect()),
        )
    }

    fn recover_call_outputs(
        &self,
        facts: Option<&[MCodeStorageFact]>,
    ) -> Result<Vec<MCodeCallOutput>, IlError> {
        match facts {
            Some(facts) => facts
                .iter()
                .copied()
                .map(|fact| self.recover_call_output(fact))
                .collect(),
            None => self
                .convention
                .outputs()
                .iter()
                .take_while(|entry| !matches!(entry.location(), MCodeStorageLocation::Stack { .. }))
                .map(|entry| {
                    let fact = entry.resolve_fact(self.registers)?.ok_or_else(|| {
                        IlError::missing_component(ECodeIr::FORM, "calling-convention output")
                    })?;
                    self.recover_call_output(fact)
                })
                .collect(),
        }
    }

    fn recover_call_output(&self, fact: MCodeStorageFact) -> Result<MCodeCallOutput, IlError> {
        match fact.location() {
            MCodeStorageLocation::Register(register) => {
                let width = self.registers.root_bits(register).ok_or_else(|| {
                    IlError::missing_component(ECodeIr::FORM, "call output register")
                })?;
                if width != fact.width() {
                    return Err(IlError::width_mismatch(ECodeIr::FORM));
                }
                Ok(MCodeCallOutput::new(
                    fact.location(),
                    [MCodeCallOutputComponent::register(register, width)],
                ))
            }
            MCodeStorageLocation::RegisterPair { high, low } => {
                let high_width = self.registers.root_bits(high).ok_or_else(|| {
                    IlError::missing_component(ECodeIr::FORM, "call output register")
                })?;
                let low_width = self.registers.root_bits(low).ok_or_else(|| {
                    IlError::missing_component(ECodeIr::FORM, "call output register")
                })?;
                if high_width
                    .checked_add(low_width)
                    .filter(|&width| width == fact.width())
                    .is_none()
                {
                    return Err(IlError::width_mismatch(ECodeIr::FORM));
                }
                Ok(MCodeCallOutput::new(
                    fact.location(),
                    [
                        MCodeCallOutputComponent::register(high, high_width),
                        MCodeCallOutputComponent::register(low, low_width),
                    ],
                ))
            }
            MCodeStorageLocation::Stack { offset } => {
                let access = self
                    .stack
                    .storage_access(offset, fact.width())
                    .ok_or_else(|| {
                        IlError::missing_component(ECodeIr::FORM, "stack call output")
                    })?;
                let object_width = self
                    .stack
                    .objects()
                    .get(access.object().index())
                    .and_then(|object| object.width())
                    .ok_or_else(|| {
                        IlError::missing_component(ECodeIr::FORM, "stack call output width")
                    })?;
                Ok(MCodeCallOutput::new(
                    fact.location(),
                    [MCodeCallOutputComponent::stack(
                        access,
                        object_width,
                        fact.width(),
                    )],
                ))
            }
        }
    }

    fn recover_exit_requirements(
        &self,
        definitions: &MCodeReachingDefs,
        facts: &[MCodeStorageFact],
    ) -> Result<Vec<MCodeExitRequirement>, IlError> {
        let mut requirements = Vec::new();
        for fact in facts {
            match fact.location() {
                MCodeStorageLocation::Register(register) => {
                    let Some(value) = definitions.value(register) else {
                        continue;
                    };
                    if self.ir.value_width(value) != Some(fact.width()) {
                        return Err(IlError::width_mismatch(ECodeIr::FORM));
                    }
                    requirements.push(MCodeExitRequirement::Register(value));
                }
                MCodeStorageLocation::RegisterPair { high, low } => {
                    for register in [high, low] {
                        let Some(value) = definitions.value(register) else {
                            continue;
                        };
                        if self.ir.value_width(value) != self.registers.root_bits(register) {
                            return Err(IlError::width_mismatch(ECodeIr::FORM));
                        }
                        requirements.push(MCodeExitRequirement::Register(value));
                    }
                }
                MCodeStorageLocation::Stack { offset } => {
                    let access =
                        self.stack
                            .storage_access(offset, fact.width())
                            .ok_or_else(|| {
                                IlError::missing_component(ECodeIr::FORM, "stack exit output")
                            })?;
                    requirements.push(MCodeExitRequirement::Stack(access));
                }
            }
        }
        Ok(requirements)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{
        IlArtefact, IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph,
        IlGraphBuilder, IlIndexRange, IlMetadata, IlValueId, RegisterBank,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeIr, ECodeOpSpec, ECodeOpcode};
    use crate::ir::{Address, FunctionId};
    use crate::lifter::resolve_language;
    use crate::storage::segments::space::AddressSpaceId;

    const RDI: u64 = 0x38;
    const RSI: u64 = 0x30;
    const RDX: u64 = 0x28;
    const RAX: u64 = 0x00;
    const RSP: u64 = 0x20;

    fn emit_value(
        builder: &mut ECodeBuilder,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let (_, results) = builder.emitter().emit(spec, operands, 1)?;
        IlValueId::try_from_index(results.start())
    }

    fn recover(ir: &ECodeIr, convention: &MCodeCallingConvention) -> MCodeAbiModel {
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let stack = MCodeStackModel::new(ir, RegisterId::new(RSP), []);
        MCodeAbiModel::new(ir, convention, &[], &[], None, &registers, &stack).unwrap()
    }

    fn recover_with_facts(
        ir: &ECodeIr,
        convention: &MCodeCallingConvention,
        facts: &MCodeFunctionFacts,
    ) -> MCodeAbiModel {
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        facts.validate(ir, &registers).unwrap();
        let stack = MCodeStackModel::new(ir, RegisterId::new(RSP), facts.stack_storage());
        facts.validate_stack(&stack).unwrap();
        MCodeAbiModel::new(ir, convention, &[], &[], Some(facts), &registers, &stack).unwrap()
    }

    fn entry(location: MCodeStorageLocation) -> MCodeCallingConventionEntry {
        MCodeCallingConventionEntry::new(location, 1, 8)
    }

    fn register(root: u64) -> MCodeCallingConventionEntry {
        entry(MCodeStorageLocation::Register(RegisterId::new(root)))
    }

    #[test]
    fn stack_offsets_are_normalised_to_the_target_address_width() {
        assert_eq!(normalise_stack_offset(0x10, 32), Ok(16));
        assert_eq!(normalise_stack_offset(0xffff_fff0, 32), Ok(-16));
        assert_eq!(normalise_stack_offset(0x10, 64), Ok(16));
        assert_eq!(normalise_stack_offset(0xffff_ffff_ffff_fff0, 64), Ok(-16));
    }

    #[test]
    fn exact_stack_facts_produce_stack_inputs_and_outputs() {
        let mut function = Function::new();
        let site = function.call();
        let ir = function.finish();
        let mut call = MCodeCallFacts::new(site);
        call.insert_input(MCodeStorageFact::new(
            MCodeStorageLocation::Stack { offset: -16 },
            128,
        ));
        call.insert_output(MCodeStorageFact::new(
            MCodeStorageLocation::Stack { offset: 8 },
            192,
        ));
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(call);

        let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
        let call = model.call(site).expect("a recovered call");
        let output = call.outputs().first().expect("a recovered stack output");
        let component = output.components().first().expect("one stack component");

        assert_eq!(
            call.args(),
            &[MCodeCallArg::Stack {
                offset: -16,
                width: 128,
            }]
        );
        assert_eq!(output.location(), MCodeStorageLocation::Stack { offset: 8 });
        assert!(matches!(
            component,
            MCodeCallOutputComponent::Stack {
                object_width: 192,
                width: 192,
                ..
            }
        ));
        assert_eq!(component.width(), 192);
    }

    #[test]
    fn exact_call_facts_preserve_input_and_output_order() {
        let mut function = Function::new();
        let rdi = function.define(RDI);
        let rax = function.define(RAX);
        let site = function.call();
        let ir = function.finish();
        let mut call = MCodeCallFacts::new(site);
        call.set_inputs([
            MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RDI)), 64),
            MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64),
        ]);
        call.set_outputs([
            MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RSI)), 64),
            MCodeStorageFact::new(
                MCodeStorageLocation::RegisterPair {
                    high: RegisterId::new(RDX),
                    low: RegisterId::new(RAX),
                },
                128,
            ),
            MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: 8 }, 192),
        ]);
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(call);

        let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
        let call = model.call(site).expect("a recovered call");

        assert_eq!(
            call.args(),
            &[MCodeCallArg::Value(rdi), MCodeCallArg::Value(rax)]
        );
        assert_eq!(
            call.outputs()
                .iter()
                .map(MCodeCallOutput::location)
                .collect::<Vec<_>>(),
            &[
                MCodeStorageLocation::Register(RegisterId::new(RSI)),
                MCodeStorageLocation::RegisterPair {
                    high: RegisterId::new(RDX),
                    low: RegisterId::new(RAX),
                },
                MCodeStorageLocation::Stack { offset: 8 },
            ]
        );
    }

    #[test]
    fn known_empty_call_facts_do_not_use_the_convention() {
        let mut function = Function::new();
        function.define(RDI);
        let site = function.call();
        let ir = function.finish();
        let mut call = MCodeCallFacts::new(site);
        call.set_inputs([]);
        call.set_outputs([]);
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(call);
        let convention = MCodeCallingConvention::new(vec![register(RDI)], vec![register(RAX)]);

        let model = recover_with_facts(&ir, &convention, &facts);
        let call = model.call(site).expect("a recovered call");

        assert!(call.args().is_empty());
        assert!(call.outputs().is_empty());
    }

    #[test]
    fn known_empty_function_outputs_do_not_use_the_fallback() {
        let mut function = Function::new();
        let rax = function.define(RAX);
        let site = function.return_();
        let ir = function.finish();
        let output =
            MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64);
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let stack = MCodeStackModel::new(&ir, RegisterId::new(RSP), []);
        let unknown = MCodeFunctionFacts::new(ir.metadata().function());
        let mut known_empty = MCodeFunctionFacts::new(ir.metadata().function());
        known_empty.set_return_live_outputs([]);

        let fallback = MCodeAbiModel::new(
            &ir,
            &MCodeCallingConvention::default(),
            &[output],
            &[],
            Some(&unknown),
            &registers,
            &stack,
        )
        .unwrap();
        let exact = MCodeAbiModel::new(
            &ir,
            &MCodeCallingConvention::default(),
            &[output],
            &[],
            Some(&known_empty),
            &registers,
            &stack,
        )
        .unwrap();

        assert_eq!(
            fallback.exit_requirements(site),
            &[MCodeExitRequirement::Register(rax)]
        );
        assert!(exact.exit_requirements(site).is_empty());
    }

    #[test]
    fn function_exit_requirements_retain_register_pairs_and_stack_storage() {
        let mut function = Function::new();
        let high = function.define(RDX);
        let low = function.define(RAX);
        let site = function.return_();
        let ir = function.finish();
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.set_return_live_outputs([
            MCodeStorageFact::new(
                MCodeStorageLocation::RegisterPair {
                    high: RegisterId::new(RDX),
                    low: RegisterId::new(RAX),
                },
                128,
            ),
            MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64),
        ]);

        let model = recover_with_facts(&ir, &MCodeCallingConvention::default(), &facts);
        let requirements = model.exit_requirements(site);

        assert_eq!(
            &requirements[..2],
            &[
                MCodeExitRequirement::Register(high),
                MCodeExitRequirement::Register(low),
            ]
        );
        assert!(matches!(requirements[2], MCodeExitRequirement::Stack(_)));
    }

    #[test]
    fn function_live_outputs_are_sorted_and_deduplicated() {
        let register =
            MCodeStorageFact::new(MCodeStorageLocation::Register(RegisterId::new(RAX)), 64);
        let stack = MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64);
        let mut facts = MCodeFunctionFacts::new(FunctionId::default());

        facts.insert_return_live_output(stack);
        facts.insert_return_live_output(register);
        facts.insert_return_live_output(stack);
        facts.set_tail_call_live_outputs([stack, register, stack]);

        assert_eq!(facts.return_live_outputs(), Some(&[register, stack][..]));
        assert_eq!(facts.tail_call_live_outputs(), Some(&[register, stack][..]));
    }

    #[test]
    fn storage_fact_validation_rejects_inconsistent_widths_and_roots() {
        let mut function = Function::new();
        let site = function.call();
        let ir = function.finish();
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let validate = |fact| {
            let mut call = MCodeCallFacts::new(site);
            call.insert_input(fact);
            let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
            facts.insert_call(call);
            facts.validate(&ir, &registers)
        };

        assert_eq!(
            validate(MCodeStorageFact::new(
                MCodeStorageLocation::Register(RegisterId::new(RDI)),
                32,
            )),
            Err(IlError::width_mismatch(ECodeIr::FORM))
        );
        assert_eq!(
            validate(MCodeStorageFact::new(
                MCodeStorageLocation::RegisterPair {
                    high: RegisterId::new(RDX),
                    low: RegisterId::new(RAX),
                },
                63,
            )),
            Err(IlError::width_mismatch(ECodeIr::FORM))
        );
        assert!(matches!(
            validate(MCodeStorageFact::new(
                MCodeStorageLocation::Register(RegisterId::new(u64::MAX)),
                64,
            )),
            Err(IlError::MissingComponent { .. })
        ));
        assert_eq!(
            validate(MCodeStorageFact::new(
                MCodeStorageLocation::Stack { offset: -8 },
                0,
            )),
            Err(IlError::width_mismatch(ECodeIr::FORM))
        );
        assert_eq!(
            validate(MCodeStorageFact::new(
                MCodeStorageLocation::Stack { offset: i64::MAX },
                16,
            )),
            Err(IlError::integer_overflow("stack storage range"))
        );
    }

    #[test]
    fn conflicting_function_exit_widths_are_rejected() {
        let function = Function::new();
        let ir = function.finish();
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.set_return_live_outputs([
            MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 32),
            MCodeStorageFact::new(MCodeStorageLocation::Stack { offset: -8 }, 64),
        ]);

        assert_eq!(
            facts.validate(&ir, &registers),
            Err(IlError::width_mismatch(ECodeIr::FORM))
        );
    }

    #[test]
    fn call_facts_reject_arithmetic_and_internal_branch_sites() {
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let left = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        let right = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        let arithmetic = builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Add, 64), [left, right], 1)
            .map(|(operation, _)| operation)
            .unwrap();
        let ir = builder.build_unchecked();
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(MCodeCallFacts::new(arithmetic));

        assert_eq!(
            facts.validate(&ir, &registers),
            Err(IlError::invalid_fact_site(arithmetic.value()))
        );

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let branch = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Branch, 0).with_address(Address::from(0x1000u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();
        builder
            .emitter()
            .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [], 0)
            .unwrap();
        builder.set_graph(IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![IlBlockId::try_from_index(1).unwrap()],
            vec![IlEdgeKinds::UNCONDITIONAL],
        ));
        let ir = builder.build_unchecked();
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(MCodeCallFacts::new(branch));

        assert_eq!(
            facts.validate(&ir, &registers),
            Err(IlError::invalid_fact_site(branch.value()))
        );
    }

    #[test]
    fn call_fact_site_validation_accepts_direct_indirect_and_tail_calls() {
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let validate = |ir: &ECodeIr, site| {
            let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
            facts.insert_call(MCodeCallFacts::new(site));
            facts.validate(ir, &registers)
        };

        let mut direct = Function::new();
        let direct_site = direct.call();
        let direct = direct.finish();
        assert_eq!(validate(&direct, direct_site), Ok(()));

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let destination = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
            [],
        )
        .unwrap();
        let indirect_site = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::CallIndirect, 0)
                    .with_address_space(AddressSpaceId::new(0)),
                [destination],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();
        let indirect = builder.build_unchecked();
        assert_eq!(validate(&indirect, indirect_site), Ok(()));

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let tail_site = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Branch, 0).with_address(Address::from(0x2000u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();
        builder.set_graph(IlGraph::new(
            vec![IlBlock::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
            )],
            Vec::new(),
            Vec::new(),
        ));
        let tail = builder.build_unchecked();
        assert_eq!(validate(&tail, tail_site), Ok(()));
    }

    struct Function {
        builder: ECodeBuilder,
        operations: usize,
    }

    impl Function {
        fn new() -> Self {
            Self {
                builder: ECodeBuilder::new(
                    IlMetadata::new(FunctionId::default(), 0),
                    IlGraph::default(),
                ),
                operations: 0,
            }
        }

        fn define(&mut self, root: u64) -> IlValueId {
            self.define_width(root, 64)
        }

        fn define_width(&mut self, root: u64, width: u32) -> IlValueId {
            let id = emit_value(
                &mut self.builder,
                ECodeOpSpec::new(ECodeOpcode::Constant, width),
                [],
            )
            .unwrap();
            self.builder
                .emitter()
                .set_value_domain(id, ECodeDomain::Register(RegisterId::new(root)))
                .unwrap();
            self.operations += 1;
            id
        }

        fn live_in(&mut self, root: u64) -> IlValueId {
            let id = emit_value(
                &mut self.builder,
                ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
                [],
            )
            .unwrap();
            self.builder
                .emitter()
                .set_value_domain(id, ECodeDomain::Register(RegisterId::new(root)))
                .unwrap();
            self.operations += 1;
            id
        }

        fn call(&mut self) -> IlOpId {
            let site = self
                .builder
                .emitter()
                .emit(
                    ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
                    [],
                    0,
                )
                .map(|(operation, _)| operation)
                .unwrap();
            self.operations += 1;
            site
        }

        fn return_(&mut self) -> IlOpId {
            let site = self
                .builder
                .emitter()
                .emit(ECodeOpSpec::new(ECodeOpcode::Return, 0), [], 0)
                .map(|(operation, _)| operation)
                .unwrap();
            self.operations += 1;
            site
        }

        fn finish(mut self) -> ECodeIr {
            self.builder.set_graph(IlGraph::new(
                vec![IlBlock::new(
                    IlIndexRange::new(0, self.operations).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::ENTRY,
                )],
                Vec::new(),
                Vec::new(),
            ));
            self.builder.build_unchecked()
        }

        fn finish_linear(self) -> ECodeIr {
            self.builder.build_unchecked()
        }
    }

    #[test]
    fn a_reaching_register_value_must_match_the_root_width() {
        let mut function = Function::new();
        function.define_width(RDI, 32);
        let site = function.call();
        let ir = function.finish();
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let mut call = MCodeCallFacts::new(site);
        call.insert_input(MCodeStorageFact::new(
            MCodeStorageLocation::Register(RegisterId::new(RDI)),
            64,
        ));
        let mut facts = MCodeFunctionFacts::new(ir.metadata().function());
        facts.insert_call(call);
        facts.validate(&ir, &registers).unwrap();
        let stack = MCodeStackModel::new(&ir, RegisterId::new(RSP), facts.stack_storage());

        let result = MCodeAbiModel::new(
            &ir,
            &MCodeCallingConvention::default(),
            &[],
            &[],
            Some(&facts),
            &registers,
            &stack,
        );

        assert_eq!(
            result.expect_err("the reaching value width must match its register root"),
            IlError::width_mismatch(ECodeIr::FORM)
        );
    }

    #[test]
    fn recovers_register_args_in_convention_order() {
        let mut function = Function::new();
        let rdi = function.define(RDI);
        let rsi = function.define(RSI);
        let site = function.call();
        let ir = function.finish();

        let convention = MCodeCallingConvention::new(
            vec![register(RDI), register(RSI), register(RDX)],
            vec![register(RAX)],
        );
        let model = recover(&ir, &convention);
        let call = model.call(site).expect("a recovered call");

        assert_eq!(
            call.args(),
            &[MCodeCallArg::Value(rdi), MCodeCallArg::Value(rsi),]
        );
        assert_eq!(
            call.outputs()[0].location(),
            MCodeStorageLocation::Register(RegisterId::new(RAX))
        );
    }

    #[test]
    fn recovers_register_args_in_a_linear_body() {
        let mut function = Function::new();
        let rdi = function.define(RDI);
        let site = function.call();
        let ir = function.finish_linear();

        let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
        let model = recover(&ir, &convention);
        let call = model.call(site).expect("a recovered call");

        assert_eq!(call.args(), &[MCodeCallArg::Value(rdi)]);
    }

    #[test]
    fn branch_heavy_abi_recovery_restores_reaching_registers_between_siblings() {
        const BRANCH_COUNT: usize = 32;

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, IlGraph::default());
        let reaching = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(1),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(reaching, ECodeDomain::Register(RegisterId::new(RDI)))
            .unwrap();

        for immediate in 1..BRANCH_COUNT {
            let sibling = emit_value(
                &mut builder,
                ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(immediate as u64 + 1),
                [],
            )
            .unwrap();
            builder
                .emitter()
                .set_value_domain(sibling, ECodeDomain::Register(RegisterId::new(RDI)))
                .unwrap();
        }
        let site = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();

        let successors = (1..=BRANCH_COUNT)
            .map(|index| IlBlockId::try_from_index(index).unwrap())
            .collect::<Vec<_>>();
        let mut blocks = vec![IlBlock::new(
            IlIndexRange::new(0, 1).unwrap(),
            IlIndexRange::new(0, BRANCH_COUNT).unwrap(),
            IlBlockProperties::ENTRY,
        )];
        blocks.extend((1..=BRANCH_COUNT).map(|index| {
            IlBlock::new(
                IlIndexRange::new(index, index + 1).unwrap(),
                IlIndexRange::EMPTY,
                IlBlockProperties::EXIT,
            )
        }));
        builder.set_graph(IlGraph::new(
            blocks,
            successors,
            vec![IlEdgeKinds::UNCONDITIONAL; BRANCH_COUNT],
        ));
        let ir = builder.build_unchecked();

        let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
        let model = recover(&ir, &convention);

        assert_eq!(
            model.call(site).expect("the final sibling call").args(),
            &[MCodeCallArg::Value(reaching)]
        );
    }

    #[test]
    fn recovers_a_register_arg_from_a_block_arg() {
        let mut graph = IlGraphBuilder::new();
        let entry = graph
            .push_block(IlIndexRange::new(0, 1).unwrap(), IlBlockProperties::ENTRY)
            .unwrap();
        let successor = graph
            .push_block(IlIndexRange::new(1, 2).unwrap(), IlBlockProperties::EXIT)
            .unwrap();
        graph
            .add_successor(entry, successor, IlEdgeKinds::FALL_THROUGH)
            .unwrap();

        let metadata = IlMetadata::new(FunctionId::default(), 0);
        let mut builder = ECodeBuilder::new(metadata, graph.build(2).unwrap());
        let initial = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(initial, ECodeDomain::Register(RegisterId::new(RDI)))
            .unwrap();
        let arg = builder.emitter().emit_block_arg(successor, 64).unwrap();
        builder
            .emitter()
            .set_value_domain(arg, ECodeDomain::Register(RegisterId::new(RDI)))
            .unwrap();
        builder.emitter().emit_edge_args([initial]).unwrap();
        let site = builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Call, 0).with_address(Address::from(0x1000u64)),
                [],
                0,
            )
            .map(|(operation, _)| operation)
            .unwrap();
        let ir = builder.build_unchecked();

        let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
        let model = recover(&ir, &convention);

        assert_eq!(
            model.call(site).expect("a recovered call").args(),
            &[MCodeCallArg::Value(arg)]
        );
    }

    #[test]
    fn arity_stops_at_the_first_unset_arg_register() {
        let mut function = Function::new();
        let rdi = function.define(RDI);
        let site = function.call();
        let ir = function.finish();

        let convention =
            MCodeCallingConvention::new(vec![register(RDI), register(RSI)], Vec::new());
        let model = recover(&ir, &convention);
        let call = model.call(site).expect("a recovered call");

        assert_eq!(call.args(), &[MCodeCallArg::Value(rdi)]);
    }

    #[test]
    fn a_register_outside_the_convention_width_range_is_an_error() {
        let mut function = Function::new();
        function.define(RDI);
        function.call();
        let ir = function.finish();
        let convention = MCodeCallingConvention::new(
            vec![MCodeCallingConventionEntry::new(
                MCodeStorageLocation::Register(RegisterId::new(RDI)),
                1,
                4,
            )],
            Vec::new(),
        );
        let registers = RegisterBank::new(resolve_language("x86:LE:64").unwrap()).unwrap();
        let stack = MCodeStackModel::new(&ir, RegisterId::new(RSP), []);

        let result = MCodeAbiModel::new(&ir, &convention, &[], &[], None, &registers, &stack);

        assert_eq!(
            result.expect_err("an incompatible convention input must fail recovery"),
            IlError::width_mismatch(ECodeIr::FORM)
        );
    }

    #[test]
    fn a_forwarded_parameter_counts_but_a_post_clobber_value_does_not() {
        let mut function = Function::new();
        let forwarded = function.live_in(RDI);
        let forwarding_call = function.call();
        function.live_in(RDI);
        let clobbered_call = function.call();
        let ir = function.finish();

        let convention = MCodeCallingConvention::new(vec![register(RDI)], Vec::new());
        let model = recover(&ir, &convention);

        assert_eq!(
            model
                .call(forwarding_call)
                .expect("a recovered forwarding call")
                .args(),
            &[MCodeCallArg::Value(forwarded)]
        );
        assert!(
            model
                .call(clobbered_call)
                .expect("a recovered clobbered call")
                .args()
                .is_empty()
        );
    }

    #[test]
    fn a_register_join_output_lowers_to_both_roots() {
        const HIGH: Varnode = Varnode::new(4, RDX, 8);
        const LOW: Varnode = Varnode::new(4, RAX, 8);
        static OUTPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
            1,
            16,
            1,
            PrototypeOperand::RegisterJoin(HIGH, LOW),
        )];

        let prototype = Prototype::new("joined", 0, 0).with_outputs(&OUTPUTS);
        let convention = MCodeCallingConvention::from_prototype(&prototype, 64, |varnode| {
            Ok(RegisterId::new(varnode.offset()))
        })
        .unwrap();

        assert_eq!(
            convention.outputs(),
            &[MCodeCallingConventionEntry::new(
                MCodeStorageLocation::RegisterPair {
                    high: RegisterId::new(RDX),
                    low: RegisterId::new(RAX),
                },
                1,
                16,
            )]
        );
    }

    #[test]
    fn an_unresolvable_register_join_is_an_error() {
        const HIGH: Varnode = Varnode::new(4, RDX, 8);
        const LOW: Varnode = Varnode::new(4, RAX, 8);
        static INPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
            1,
            16,
            1,
            PrototypeOperand::RegisterJoin(HIGH, LOW),
        )];
        static OUTPUTS: [PrototypeEntry; 1] = [PrototypeEntry::new(
            1,
            16,
            1,
            PrototypeOperand::RegisterJoin(HIGH, LOW),
        )];

        let input_prototype = Prototype::new("joined", 0, 0).with_inputs(&INPUTS);
        let output_prototype = Prototype::new("joined", 0, 0).with_outputs(&OUTPUTS);
        let missing_root =
            || IlError::missing_component(ECodeIr::FORM, "call-convention register root");

        let input_error = MCodeCallingConvention::from_prototype(&input_prototype, 64, |varnode| {
            (varnode.offset() == HIGH.offset())
                .then_some(RegisterId::new(varnode.offset()))
                .ok_or_else(missing_root)
        });
        assert!(matches!(input_error, Err(IlError::MissingComponent { .. })));

        let output_error =
            MCodeCallingConvention::from_prototype(&output_prototype, 64, |varnode| {
                (varnode.offset() == HIGH.offset())
                    .then_some(RegisterId::new(varnode.offset()))
                    .ok_or_else(missing_root)
            });
        assert!(matches!(
            output_error,
            Err(IlError::MissingComponent { .. })
        ));
    }

    #[test]
    fn recovers_a_register_join_as_a_pair() {
        let mut function = Function::new();
        let high = function.define(RDX);
        let low = function.define(RAX);
        let site = function.call();
        let ir = function.finish();

        let convention = MCodeCallingConvention::new(
            vec![MCodeCallingConventionEntry::new(
                MCodeStorageLocation::RegisterPair {
                    high: RegisterId::new(RDX),
                    low: RegisterId::new(RAX),
                },
                1,
                16,
            )],
            Vec::new(),
        );
        let model = recover(&ir, &convention);
        let call = model.call(site).expect("a recovered call");

        assert_eq!(call.args(), &[MCodeCallArg::Pair { high, low }]);
    }
}
