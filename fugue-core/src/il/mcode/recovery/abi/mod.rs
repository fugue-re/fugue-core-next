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

    fn stack_storage(&self) -> impl Iterator<Item = MCodeStorageFact> + '_ {
        self.inputs
            .iter()
            .chain(&self.outputs)
            .flat_map(|facts| facts.iter().copied())
            .filter(|fact| matches!(fact.location(), MCodeStorageLocation::Stack { .. }))
    }

    fn validate(&self, ir: &ECodeIr, registers: &RegisterBank) -> Result<(), IlError> {
        let operation = ir.ops().get(self.site.index()).ok_or_else(|| {
            IlError::range_out_of_bounds(self.site.index() + 1, ir.ops().len())
        })?;
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
        for (site, operation) in self
            .ir
            .graph()
            .ops_for_block(block, self.ir.ops())
        {
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

    fn is_reaching_input(&self, value: IlValueId) -> bool {
        self.ir.defining_op(value).is_none_or(|operation| {
            operation.opcode() != ECodeOpcode::Undefined || self.entry_live_inputs.contains(&value)
        })
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
mod test;
