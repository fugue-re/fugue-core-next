use crate::pcode::Varnode;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReturnAddress {
    Register(Varnode),
    StackRelative { offset: u64, size: usize },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Convention {
    name: &'static str,
    stack_pointer: Varnode,
    return_address: Option<ReturnAddress>,
    prototypes: &'static [Prototype],
}

impl Convention {
    pub const fn new(name: &'static str, stack_pointer: Varnode) -> Self {
        Self {
            name,
            stack_pointer,
            return_address: None,
            prototypes: &[],
        }
    }

    pub const fn with_return_address(mut self, return_address: ReturnAddress) -> Self {
        self.return_address = Some(return_address);
        self
    }

    pub const fn with_prototypes(mut self, prototypes: &'static [Prototype]) -> Self {
        self.prototypes = prototypes;
        self
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn stack_pointer(&self) -> Varnode {
        self.stack_pointer
    }

    pub const fn return_address(&self) -> Option<ReturnAddress> {
        self.return_address
    }

    pub const fn prototypes(&self) -> &'static [Prototype] {
        self.prototypes
    }

    pub const fn default_prototype(&self) -> Option<&'static Prototype> {
        self.prototypes.first()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PrototypeOperand {
    Register(Varnode),
    RegisterJoin(Varnode, Varnode),
    StackRelative(u64),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrototypeEntry {
    min_size: usize,
    max_size: usize,
    alignment: u64,
    meta_type: Option<&'static str>,
    extension: Option<&'static str>,
    operand: PrototypeOperand,
}

impl PrototypeEntry {
    pub const fn new(
        min_size: usize,
        max_size: usize,
        alignment: u64,
        operand: PrototypeOperand,
    ) -> Self {
        Self {
            min_size,
            max_size,
            alignment,
            meta_type: None,
            extension: None,
            operand,
        }
    }

    pub const fn with_meta_type(mut self, meta_type: &'static str) -> Self {
        self.meta_type = Some(meta_type);
        self
    }

    pub const fn with_extension(mut self, extension: &'static str) -> Self {
        self.extension = Some(extension);
        self
    }

    pub const fn min_size(&self) -> usize {
        self.min_size
    }

    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    pub const fn alignment(&self) -> u64 {
        self.alignment
    }

    pub const fn meta_type(&self) -> Option<&'static str> {
        self.meta_type
    }

    pub const fn extension(&self) -> Option<&'static str> {
        self.extension
    }

    pub const fn operand(&self) -> &PrototypeOperand {
        &self.operand
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Prototype {
    name: &'static str,
    extra_pop: u64,
    stack_shift: u64,
    inputs: &'static [PrototypeEntry],
    outputs: &'static [PrototypeEntry],
    unaffected: &'static [PrototypeOperand],
    killed_by_call: &'static [PrototypeOperand],
    likely_trashed: &'static [PrototypeOperand],
}

impl Prototype {
    pub const fn new(name: &'static str, extra_pop: u64, stack_shift: u64) -> Self {
        Self {
            name,
            extra_pop,
            stack_shift,
            inputs: &[],
            outputs: &[],
            unaffected: &[],
            killed_by_call: &[],
            likely_trashed: &[],
        }
    }

    pub const fn with_inputs(mut self, inputs: &'static [PrototypeEntry]) -> Self {
        self.inputs = inputs;
        self
    }

    pub const fn with_outputs(mut self, outputs: &'static [PrototypeEntry]) -> Self {
        self.outputs = outputs;
        self
    }

    pub const fn with_unaffected(mut self, unaffected: &'static [PrototypeOperand]) -> Self {
        self.unaffected = unaffected;
        self
    }

    pub const fn with_killed_by_call(
        mut self,
        killed_by_call: &'static [PrototypeOperand],
    ) -> Self {
        self.killed_by_call = killed_by_call;
        self
    }

    pub const fn with_likely_trashed(
        mut self,
        likely_trashed: &'static [PrototypeOperand],
    ) -> Self {
        self.likely_trashed = likely_trashed;
        self
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn extra_pop(&self) -> u64 {
        self.extra_pop
    }

    pub const fn stack_shift(&self) -> u64 {
        self.stack_shift
    }

    pub const fn inputs(&self) -> &'static [PrototypeEntry] {
        self.inputs
    }

    pub const fn outputs(&self) -> &'static [PrototypeEntry] {
        self.outputs
    }

    pub const fn unaffected(&self) -> &'static [PrototypeOperand] {
        self.unaffected
    }

    pub const fn killed_by_call(&self) -> &'static [PrototypeOperand] {
        self.killed_by_call
    }

    pub const fn likely_trashed(&self) -> &'static [PrototypeOperand] {
        self.likely_trashed
    }
}
