use rustc_hash::FxHashMap;

use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{IlArtefact, IlError};
use crate::il::ecode::{ECodeExprOpcode, ECodeSink, ECodeStmtOpcode};
use crate::il::pcode::{
    FlagId, PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode, RegisterBank,
    RegisterId, RegisterSlice,
};
use crate::lifter::Varnode;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum LocationRole {
    Address,
    Value,
}

#[derive(Debug)]
pub(crate) struct ECodeLiftScratch<V> {
    intrinsic_args: Vec<Varnode>,
    operands: Vec<V>,
}

impl<V> Default for ECodeLiftScratch<V> {
    fn default() -> Self {
        Self {
            intrinsic_args: Vec::new(),
            operands: Vec::new(),
        }
    }
}

pub(crate) struct ECodeLifter<'a, 'b, S: ECodeSink> {
    arch: &'a Arch,
    source: &'a PCodeIr,
    sink: &'b mut S,
    register_bank: RegisterBank,
    flags: FxHashMap<PCodeLocation, FlagId>,
    values: FxHashMap<(PCodeLocationId, LocationRole), S::Value>,
    register_values: FxHashMap<RegisterId, S::Value>,
    register_reads: FxHashMap<PCodeLocationId, S::Value>,
    flag_values: FxHashMap<FlagId, S::Value>,
    scratch: &'b mut ECodeLiftScratch<S::Value>,
    effects: usize,
}

impl<'a, 'b, S: ECodeSink> ECodeLifter<'a, 'b, S> {
    pub(crate) fn new(
        source: &'a PCodeIr,
        arch: &'a Arch,
        sink: &'b mut S,
        scratch: &'b mut ECodeLiftScratch<S::Value>,
    ) -> Result<Self, IlError> {
        let language = arch.language();
        let flags = arch
            .flags()
            .iter()
            .map(|flag| {
                let variable = flag.variable();
                (
                    PCodeLocation::from_varnode(language, &variable),
                    FlagId::new(variable.offset()),
                )
            })
            .collect();

        Ok(Self {
            arch,
            source,
            sink,
            register_bank: RegisterBank::new(language, source)?,
            flags,
            values: FxHashMap::default(),
            register_values: FxHashMap::default(),
            register_reads: FxHashMap::default(),
            flag_values: FxHashMap::default(),
            scratch,
            effects: 0,
        })
    }

    pub(crate) fn lift(&mut self, cancellation: &CancellationToken) -> Result<Vec<u32>, IlError> {
        let mut offsets = Vec::with_capacity(self.source.operations().len() + 1);
        let mut source_span = 0usize;

        for (index, operation) in self.source.operations().iter().enumerate() {
            cancellation.check()?;
            while let Some(span) = self
                .source
                .source_spans()
                .get(source_span)
                .filter(|span| span.destination().start() == index)
            {
                self.sink.begin_instruction(span.address())?;
                self.values.clear();
                self.register_values.clear();
                self.register_reads.clear();
                self.flag_values.clear();
                source_span += 1;
            }
            offsets.push(self.effects as u32);
            self.lift_operation(operation)?;
        }

        offsets.push(self.effects as u32);

        Ok(offsets)
    }

    pub(crate) fn register_bank(&self) -> &RegisterBank {
        &self.register_bank
    }

    fn lift_operation(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        match operation.opcode() {
            PCodeOpcode::Store => self.lift_store(operation),
            PCodeOpcode::Branch => self.lift_direct_flow(operation, ECodeStmtOpcode::Branch),
            PCodeOpcode::CBranch => {
                self.lift_direct_flow(operation, ECodeStmtOpcode::ConditionalBranch)
            }
            PCodeOpcode::IBranch => {
                self.lift_indirect_flow(operation, ECodeStmtOpcode::BranchIndirect)
            }
            PCodeOpcode::Call => self.lift_direct_flow(operation, ECodeStmtOpcode::Call),
            PCodeOpcode::ICall => self.lift_indirect_flow(operation, ECodeStmtOpcode::CallIndirect),
            PCodeOpcode::Return => self.lift_indirect_flow(operation, ECodeStmtOpcode::Return),
            PCodeOpcode::UserOp if operation.output().is_none() => self.lift_intrinsic(operation),
            opcode => self.lift_expression_operation(operation, opcode),
        }
    }

    fn lift_intrinsic(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        let intrinsic = u64::from(operation.immediate());
        if self.is_trap_intrinsic(operation) {
            self.sink.trap(intrinsic, operation.address_space())?;
        } else {
            self.lift_operand_values(operation, None)?;
            self.sink
                .intrinsic(intrinsic, &self.scratch.operands, operation.address_space())?;
        }
        self.effects += 1;

        Ok(())
    }

    fn is_trap_intrinsic(&mut self, operation: &PCodeOp) -> bool {
        self.scratch.intrinsic_args.clear();
        for operand in self.source.operation_operands_for(operation) {
            let location = self.location(*operand);
            self.scratch.intrinsic_args.push(Varnode::new(
                location.lifter_space().value(),
                location.offset(),
                location.size(),
            ));
        }
        self.arch.is_trap_intrinsic(
            u16::try_from(operation.immediate())
                .expect("PCode user-op identifier originated as u16"),
            &self.scratch.intrinsic_args,
        )
    }

    fn lift_expression_operation(
        &mut self,
        operation: &PCodeOp,
        opcode: PCodeOpcode,
    ) -> Result<(), IlError> {
        let Some(output) = operation.output() else {
            return Err(IlError::missing_component(PCodeIr::FORM, "output"));
        };
        let output_width = self.location(output).bits();
        let mut immediate = u64::from(operation.immediate());
        if opcode == PCodeOpcode::Subpiece {
            let source = self.source.operation_operands_for(operation)[0];
            let offset = self.source.operation_operands_for(operation)[1];
            let source = self.lift_location(source, LocationRole::Value)?;
            let location = *self.location(offset);
            if !location.is_constant() {
                return Err(IlError::missing_component(
                    PCodeIr::FORM,
                    "constant subpiece offset",
                ));
            }
            immediate = location
                .offset()
                .checked_mul(8)
                .ok_or_else(|| IlError::integer_overflow("subpiece offset"))?;
            self.scratch.operands.clear();
            self.scratch.operands.push(source);
        } else {
            let address_operand = (opcode == PCodeOpcode::Load).then_some(0);
            self.lift_operand_values(operation, address_operand)?;
        }
        let expression = self.sink.apply(
            ECodeExprOpcode::from_pcode(opcode)?,
            output_width,
            &self.scratch.operands,
            immediate,
            operation.address_space(),
        )?;

        self.assign_output(output, expression)
    }

    fn assign_output(&mut self, output: PCodeLocationId, value: S::Value) -> Result<(), IlError> {
        let location = *self.location(output);
        if let Some(flag) = self.flags.get(&location).copied() {
            self.flag_values.insert(flag, value);
            self.sink.write_flag(flag, value)?;
            self.effects += 1;
        } else if location.is_register() {
            self.assign_register(&location, value)?;
        } else {
            self.values.insert((output, LocationRole::Value), value);
        }

        Ok(())
    }

    fn assign_register(
        &mut self,
        location: &PCodeLocation,
        expression: S::Value,
    ) -> Result<(), IlError> {
        let slice = self.register_bank.slice(location, self.arch.endian())?;
        let value = if slice.is_root() {
            expression
        } else {
            let root = self.register_value(slice)?;
            self.sink.apply(
                ECodeExprOpcode::Insert,
                slice.root_bits(),
                &[root, expression],
                u64::from(slice.offset()) * 8,
                None,
            )?
        };

        self.register_reads.clear();
        let write_start = u128::from(location.offset());
        let write_end = write_start + u128::from(location.size());
        for (flag_location, flag) in &self.flags {
            if flag_location.lifter_space() != location.lifter_space() {
                continue;
            }
            let flag_start = u128::from(flag_location.offset());
            let flag_end = flag_start + u128::from(flag_location.size());
            if write_start < flag_end && flag_start < write_end {
                self.flag_values.remove(flag);
            }
        }
        self.register_values.insert(slice.root(), value);
        self.sink.write_register(slice.root(), value)?;
        self.effects += 1;

        Ok(())
    }

    fn lift_store(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        self.lift_operand_values(operation, Some(0))?;
        self.sink
            .store(&self.scratch.operands, operation.address_space())?;
        self.effects += 1;

        Ok(())
    }

    fn lift_direct_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeStmtOpcode,
    ) -> Result<(), IlError> {
        self.scratch.operands.clear();
        for operand_index in 1..self.source.operation_operands_for(operation).len() {
            let operand = self.source.operation_operands_for(operation)[operand_index];
            let operand = self.lift_location(operand, LocationRole::Value)?;
            self.scratch.operands.push(operand);
        }
        let target = self
            .source
            .target(operation.immediate())
            .expect("direct flow target is within the target pool");

        self.sink
            .direct_flow(opcode, target.address(), &self.scratch.operands)?;
        self.effects += 1;

        Ok(())
    }

    fn lift_indirect_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeStmtOpcode,
    ) -> Result<(), IlError> {
        self.lift_operand_values(operation, Some(0))?;
        self.sink
            .indirect_flow(opcode, &self.scratch.operands, operation.address_space())?;
        self.effects += 1;

        Ok(())
    }

    fn lift_operand_values(
        &mut self,
        operation: &PCodeOp,
        address_operand: Option<usize>,
    ) -> Result<(), IlError> {
        self.scratch.operands.clear();
        for operand_index in 0..self.source.operation_operands_for(operation).len() {
            let operand = self.source.operation_operands_for(operation)[operand_index];
            let role = if address_operand == Some(operand_index) {
                LocationRole::Address
            } else {
                LocationRole::Value
            };
            let operand = self.lift_location(operand, role)?;
            self.scratch.operands.push(operand);
        }

        Ok(())
    }

    fn lift_location(
        &mut self,
        id: PCodeLocationId,
        role: LocationRole,
    ) -> Result<S::Value, IlError> {
        let location = *self.location(id);
        let key = if location.is_constant() {
            (id, role)
        } else {
            (id, LocationRole::Value)
        };
        if let Some(value) = self.values.get(&key).copied() {
            return Ok(value);
        }

        let value = if location.is_constant() {
            match role {
                LocationRole::Address => self.sink.address(location.bits(), location.offset())?,
                LocationRole::Value => self.sink.constant(location.bits(), location.offset())?,
            }
        } else if let Some(flag) = self.flags.get(&location).copied() {
            if let Some(value) = self.flag_values.get(&flag).copied() {
                return Ok(value);
            }
            let value = self.sink.read_flag(flag, location.bits())?;
            self.flag_values.insert(flag, value);
            return Ok(value);
        } else if location.is_register() {
            return self.lift_register(id, &location);
        } else {
            self.sink
                .undefined(location.bits(), u64::from(id.value()))?
        };

        self.values.insert(key, value);

        Ok(value)
    }

    fn lift_register(
        &mut self,
        id: PCodeLocationId,
        location: &PCodeLocation,
    ) -> Result<S::Value, IlError> {
        if let Some(value) = self.register_reads.get(&id).copied() {
            return Ok(value);
        }

        let slice = self.register_bank.slice(location, self.arch.endian())?;
        let root = self.register_value(slice)?;
        let value = if slice.is_root() {
            root
        } else {
            self.sink.apply(
                ECodeExprOpcode::Extract,
                slice.bits(),
                &[root],
                u64::from(slice.offset()) * 8,
                None,
            )?
        };
        self.register_reads.insert(id, value);

        Ok(value)
    }

    fn register_value(&mut self, slice: RegisterSlice) -> Result<S::Value, IlError> {
        if let Some(value) = self.register_values.get(&slice.root()).copied() {
            return Ok(value);
        }

        let value = self.sink.read_register(slice.root(), slice.root_bits())?;
        self.register_values.insert(slice.root(), value);

        Ok(value)
    }

    fn location(&self, id: PCodeLocationId) -> &PCodeLocation {
        self.source
            .location(id)
            .expect("location id is within the location pool")
    }
}
