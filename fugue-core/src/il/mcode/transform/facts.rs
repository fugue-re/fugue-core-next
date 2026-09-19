use rustc_hash::FxHashMap;

use crate::il::common::{IlArtefact, IlError, IlOpId, RegisterBank, RegisterId};
use crate::il::ecode::{ECodeIr, ECodeOpcode};
use crate::il::mcode::transform::abi::MCodeStorageLocation;
use crate::il::mcode::transform::stack::MCodeStackModel;
use crate::ir::FunctionId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MCodeStorageFact {
    location: MCodeStorageLocation,
    width: u32,
}

impl MCodeStorageFact {
    pub(crate) const fn new(location: MCodeStorageLocation, width: u32) -> Self {
        Self { location, width }
    }

    pub const fn new_register(register: RegisterId, width: u32) -> Self {
        Self::new(MCodeStorageLocation::Register(register), width)
    }

    pub const fn new_register_pair(high: RegisterId, low: RegisterId, width: u32) -> Self {
        Self::new(MCodeStorageLocation::RegisterPair { high, low }, width)
    }

    pub const fn new_stack(offset: i64, width: u32) -> Self {
        Self::new(MCodeStorageLocation::Stack { offset }, width)
    }

    pub(crate) const fn location(&self) -> MCodeStorageLocation {
        self.location
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn register_id(&self) -> Option<RegisterId> {
        match self.location {
            MCodeStorageLocation::Register(register) => Some(register),
            MCodeStorageLocation::RegisterPair { .. } | MCodeStorageLocation::Stack { .. } => None,
        }
    }

    pub const fn register_pair(&self) -> Option<(RegisterId, RegisterId)> {
        match self.location {
            MCodeStorageLocation::RegisterPair { high, low } => Some((high, low)),
            MCodeStorageLocation::Register(_) | MCodeStorageLocation::Stack { .. } => None,
        }
    }

    pub const fn stack_offset(&self) -> Option<i64> {
        match self.location {
            MCodeStorageLocation::Stack { offset } => Some(offset),
            MCodeStorageLocation::Register(_) | MCodeStorageLocation::RegisterPair { .. } => None,
        }
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
