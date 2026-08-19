use rustc_hash::FxHashMap;

use super::buffer::PCodeToECodeBuffer;
use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{
    FlagId, IlArtefact, IlError, IlExprId, IlIndexMapper, RegisterBank, RegisterId, RegisterRange,
    RegisterSlice,
};
use crate::il::ecode::ECodeOpcode;
use crate::il::pcode::{PCodeIr, PCodeLocation, PCodeLocationId, PCodeOp, PCodeOpcode};
use crate::lifter::Varnode;
use crate::platform::Platform;
use crate::storage::segments::space::AddressSpaceId;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum LocationRole {
    Address,
    Value,
}

fn ecode_opcode(opcode: PCodeOpcode) -> Result<ECodeOpcode, IlError> {
    match opcode {
        PCodeOpcode::BoolAnd => Ok(ECodeOpcode::BoolAnd),
        PCodeOpcode::BoolNot => Ok(ECodeOpcode::BoolNot),
        PCodeOpcode::BoolOr => Ok(ECodeOpcode::BoolOr),
        PCodeOpcode::BoolXor => Ok(ECodeOpcode::BoolXor),
        PCodeOpcode::Copy => Ok(ECodeOpcode::Copy),
        PCodeOpcode::CountLeadingZeros => Ok(ECodeOpcode::CountLeadingZeros),
        PCodeOpcode::CountOnes => Ok(ECodeOpcode::CountOnes),
        PCodeOpcode::FloatAbs => Ok(ECodeOpcode::FloatAbs),
        PCodeOpcode::FloatAdd => Ok(ECodeOpcode::FloatAdd),
        PCodeOpcode::FloatCeiling => Ok(ECodeOpcode::FloatCeiling),
        PCodeOpcode::FloatDiv => Ok(ECodeOpcode::FloatDiv),
        PCodeOpcode::FloatEq => Ok(ECodeOpcode::FloatEqual),
        PCodeOpcode::FloatToFloat => Ok(ECodeOpcode::FloatToFloat),
        PCodeOpcode::FloatFloor => Ok(ECodeOpcode::FloatFloor),
        PCodeOpcode::IntToFloat => Ok(ECodeOpcode::IntToFloat),
        PCodeOpcode::FloatLess => Ok(ECodeOpcode::FloatLess),
        PCodeOpcode::FloatLessEq => Ok(ECodeOpcode::FloatLessEqual),
        PCodeOpcode::FloatMul => Ok(ECodeOpcode::FloatMul),
        PCodeOpcode::FloatIsNan => Ok(ECodeOpcode::FloatIsNan),
        PCodeOpcode::FloatNeg => Ok(ECodeOpcode::FloatNegate),
        PCodeOpcode::FloatNotEq => Ok(ECodeOpcode::FloatNotEqual),
        PCodeOpcode::FloatRound => Ok(ECodeOpcode::FloatRound),
        PCodeOpcode::FloatSqrt => Ok(ECodeOpcode::FloatSqrt),
        PCodeOpcode::FloatSub => Ok(ECodeOpcode::FloatSub),
        PCodeOpcode::FloatToInt => Ok(ECodeOpcode::FloatToInt),
        PCodeOpcode::IntAdd => Ok(ECodeOpcode::Add),
        PCodeOpcode::IntAnd => Ok(ECodeOpcode::And),
        PCodeOpcode::IntCarry => Ok(ECodeOpcode::Carry),
        PCodeOpcode::IntDiv => Ok(ECodeOpcode::UnsignedDiv),
        PCodeOpcode::IntEq => Ok(ECodeOpcode::IntEqual),
        PCodeOpcode::IntLeftShift => Ok(ECodeOpcode::LeftShift),
        PCodeOpcode::IntLess => Ok(ECodeOpcode::IntLess),
        PCodeOpcode::IntLessEq => Ok(ECodeOpcode::IntLessEqual),
        PCodeOpcode::IntMul => Ok(ECodeOpcode::Mul),
        PCodeOpcode::IntNeg => Ok(ECodeOpcode::Negate),
        PCodeOpcode::IntNot => Ok(ECodeOpcode::Not),
        PCodeOpcode::IntNotEq => Ok(ECodeOpcode::IntNotEqual),
        PCodeOpcode::IntOr => Ok(ECodeOpcode::Or),
        PCodeOpcode::IntRem => Ok(ECodeOpcode::UnsignedRem),
        PCodeOpcode::IntRightShift => Ok(ECodeOpcode::LogicalRightShift),
        PCodeOpcode::IntSignedBorrow => Ok(ECodeOpcode::SignedBorrow),
        PCodeOpcode::IntSignedCarry => Ok(ECodeOpcode::SignedCarry),
        PCodeOpcode::IntSignedDiv => Ok(ECodeOpcode::SignedDiv),
        PCodeOpcode::IntSignedLess => Ok(ECodeOpcode::IntSignedLess),
        PCodeOpcode::IntSignedLessEq => Ok(ECodeOpcode::IntSignedLessEqual),
        PCodeOpcode::IntSignedRem => Ok(ECodeOpcode::SignedRem),
        PCodeOpcode::IntSignedRightShift => Ok(ECodeOpcode::ArithmeticRightShift),
        PCodeOpcode::IntSub => Ok(ECodeOpcode::Sub),
        PCodeOpcode::IntXor => Ok(ECodeOpcode::Xor),
        PCodeOpcode::Load => Ok(ECodeOpcode::Load),
        PCodeOpcode::SignExt => Ok(ECodeOpcode::SignExtend),
        PCodeOpcode::Subpiece => Ok(ECodeOpcode::Extract),
        PCodeOpcode::UserOp => Ok(ECodeOpcode::IntrinsicResult),
        PCodeOpcode::ZeroExt => Ok(ECodeOpcode::ZeroExtend),
        PCodeOpcode::Branch
        | PCodeOpcode::CBranch
        | PCodeOpcode::Call
        | PCodeOpcode::IBranch
        | PCodeOpcode::ICall
        | PCodeOpcode::Return
        | PCodeOpcode::Store => Err(IlError::unsupported_opcode(PCodeIr::FORM)),
    }
}

#[derive(Debug, Default)]
pub(crate) struct PCodeToECodeLiftScratch {
    intrinsic_args: Vec<Varnode>,
    operands: Vec<IlExprId>,
}

pub(crate) struct PCodeToECodeLifter<'a, 'b> {
    arch: &'a Arch,
    source: &'a PCodeIr,
    buffer: PCodeToECodeBuffer,
    register_bank: RegisterBank,
    flags: FxHashMap<PCodeLocation, FlagId>,
    values: FxHashMap<(PCodeLocationId, LocationRole), IlExprId>,
    register_values: FxHashMap<RegisterId, IlExprId>,
    register_reads: FxHashMap<PCodeLocationId, IlExprId>,
    flag_values: FxHashMap<FlagId, IlExprId>,
    scratch: &'b mut PCodeToECodeLiftScratch,
    space: Option<AddressSpaceId>,
    effects: usize,
}

impl<'a, 'b> PCodeToECodeLifter<'a, 'b> {
    pub(crate) fn new(
        source: &'a PCodeIr,
        arch: &'a Arch,
        scratch: &'b mut PCodeToECodeLiftScratch,
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

        let ranges = source
            .locations()
            .iter()
            .filter(|location| location.is_register())
            .map(|location| RegisterRange::new(location.offset(), usize::from(location.size())))
            .collect::<Result<Vec<_>, _>>()?;
        let mut register_bank = RegisterBank::new(language)?;
        register_bank.insert_ranges(ranges);

        Ok(Self {
            arch,
            source,
            buffer: PCodeToECodeBuffer::default(),
            register_bank,
            flags,
            values: FxHashMap::default(),
            register_values: FxHashMap::default(),
            register_reads: FxHashMap::default(),
            flag_values: FxHashMap::default(),
            scratch,
            space: None,
            effects: 0,
        })
    }

    fn location(&self, id: PCodeLocationId) -> &PCodeLocation {
        self.source
            .location(id)
            .expect("location id is within the location pool")
    }

    pub(crate) fn lift(
        mut self,
        platform: &Platform,
        cancellation: &CancellationToken,
    ) -> Result<(PCodeToECodeBuffer, IlIndexMapper), IlError> {
        let mut operation_map = Vec::with_capacity(self.source.ops().len() + 1);
        let mut source_span = 0usize;

        for (index, operation) in self.source.ops().iter().enumerate() {
            cancellation.check()?;
            while let Some(span) = self
                .source
                .source_spans()
                .get(source_span)
                .filter(|span| span.destination().start() == index)
            {
                let address = span.address();
                self.space = Some(address.space());
                self.values.clear();
                self.register_values.clear();
                self.register_reads.clear();
                self.flag_values.clear();
                source_span += 1;
            }
            operation_map.push(self.effects);
            self.lift_op(operation)?;
        }

        operation_map.push(self.effects);

        let operation_map = IlIndexMapper::new(operation_map)?;
        let call_preserved_registers = self
            .register_bank
            .call_preserved_registers(platform.compiler_spec_id())?;
        self.buffer
            .set_call_preserved_registers(call_preserved_registers);

        Ok((self.buffer, operation_map))
    }

    fn lift_op(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        match operation.opcode() {
            PCodeOpcode::Store => self.lift_store(operation),
            PCodeOpcode::Branch => self.lift_direct_flow(operation, ECodeOpcode::Branch),
            PCodeOpcode::CBranch => {
                self.lift_direct_flow(operation, ECodeOpcode::ConditionalBranch)
            }
            PCodeOpcode::IBranch => self.lift_indirect_flow(operation, ECodeOpcode::BranchIndirect),
            PCodeOpcode::Call => self.lift_direct_flow(operation, ECodeOpcode::Call),
            PCodeOpcode::ICall => self.lift_indirect_flow(operation, ECodeOpcode::CallIndirect),
            PCodeOpcode::Return => self.lift_indirect_flow(operation, ECodeOpcode::Return),
            PCodeOpcode::UserOp if operation.output().is_none() => self.lift_intrinsic(operation),
            opcode => self.lift_expression_op(operation, opcode),
        }
    }

    fn lift_intrinsic(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        let intrinsic = u64::from(operation.immediate());
        if self.is_trap_intrinsic(operation) {
            self.buffer.trap(intrinsic, operation.address_space())?;
        } else {
            self.lift_operand_values(operation, None)?;
            self.buffer
                .intrinsic(intrinsic, &self.scratch.operands, operation.address_space())?;
        }
        self.effects += 1;

        Ok(())
    }

    fn is_trap_intrinsic(&mut self, operation: &PCodeOp) -> bool {
        self.scratch.intrinsic_args.clear();
        for operand in self.source.op_operands_for(operation) {
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

    fn lift_expression_op(
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
            let source = self.source.op_operands_for(operation)[0];
            let offset = self.source.op_operands_for(operation)[1];
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
        let expression = self.buffer.apply(
            ecode_opcode(opcode)?,
            output_width,
            &self.scratch.operands,
            immediate,
            operation.address_space(),
        )?;

        self.assign_output(output, expression)
    }

    fn assign_output(&mut self, id: PCodeLocationId, value: IlExprId) -> Result<(), IlError> {
        let location = *self.location(id);
        if let Some(flag) = self.flags.get(&location).copied() {
            self.flag_values.insert(flag, value);
            self.buffer.write_flag(flag, value)?;
            self.effects += 1;
        } else if location.is_register() {
            self.assign_register(&location, value)?;
        } else if location.lifter_space().value() == self.arch.language().default_space() {
            self.lift_memory_write(&location, value)?;
        } else {
            self.values.insert((id, LocationRole::Value), value);
        }

        Ok(())
    }

    fn assign_register(
        &mut self,
        location: &PCodeLocation,
        expression: IlExprId,
    ) -> Result<(), IlError> {
        let range = RegisterRange::new(location.offset(), usize::from(location.size()))?;
        let slice = self
            .register_bank
            .slice(range)?
            .ok_or_else(|| IlError::missing_component(PCodeIr::FORM, "register root"))?;
        let value = if slice.is_root() {
            expression
        } else {
            let root = self.register_value(slice)?;
            self.buffer.apply(
                ECodeOpcode::Insert,
                slice.root_bits(),
                &[root, expression],
                u64::from(slice.byte_offset()) * 8,
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
        self.buffer.write_register(slice.root(), value)?;
        self.effects += 1;

        Ok(())
    }

    fn lift_store(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        self.lift_operand_values(operation, Some(0))?;
        self.buffer
            .store(&self.scratch.operands, operation.address_space())?;
        self.effects += 1;

        Ok(())
    }

    fn lift_direct_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeOpcode,
    ) -> Result<(), IlError> {
        self.scratch.operands.clear();
        for operand_index in 1..self.source.op_operands_for(operation).len() {
            let operand = self.source.op_operands_for(operation)[operand_index];
            let operand = self.lift_location(operand, LocationRole::Value)?;
            self.scratch.operands.push(operand);
        }
        let target = self
            .source
            .target(
                operation
                    .target()
                    .expect("direct flow operation has a target identifier"),
            )
            .expect("direct flow target is within the target pool");

        self.buffer
            .direct_flow(opcode, target.address(), &self.scratch.operands)?;
        self.effects += 1;

        Ok(())
    }

    fn lift_indirect_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeOpcode,
    ) -> Result<(), IlError> {
        self.lift_operand_values(operation, Some(0))?;
        self.buffer
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
        for operand_index in 0..self.source.op_operands_for(operation).len() {
            let operand = self.source.op_operands_for(operation)[operand_index];
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
    ) -> Result<IlExprId, IlError> {
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
                LocationRole::Address => self.buffer.address(location.bits(), location.offset())?,
                LocationRole::Value => self.buffer.constant(location.bits(), location.offset())?,
            }
        } else if let Some(flag) = self.flags.get(&location).copied() {
            if let Some(value) = self.flag_values.get(&flag).copied() {
                return Ok(value);
            }
            let value = self.buffer.read_flag(flag, location.bits())?;
            self.flag_values.insert(flag, value);
            return Ok(value);
        } else if location.is_register() {
            return self.lift_register(id, &location);
        } else if location.lifter_space().value() == self.arch.language().default_space() {
            return self.lift_memory_read(&location);
        } else {
            self.buffer
                .undefined(location.bits(), u64::from(id.value()))?
        };

        self.values.insert(key, value);

        Ok(value)
    }

    fn lift_memory_read(&mut self, location: &PCodeLocation) -> Result<IlExprId, IlError> {
        let space = self
            .space
            .expect("operations are preceded by an instruction span");
        let pointer = self
            .buffer
            .address(self.arch.language().address_bits(), location.offset())?;
        self.buffer.apply(
            ECodeOpcode::Load,
            location.bits(),
            &[pointer],
            u64::from(location.lifter_space().value()),
            Some(space),
        )
    }

    fn lift_memory_write(
        &mut self,
        location: &PCodeLocation,
        value: IlExprId,
    ) -> Result<(), IlError> {
        let space = self
            .space
            .expect("operations are preceded by an instruction span");
        let pointer = self
            .buffer
            .address(self.arch.language().address_bits(), location.offset())?;
        self.buffer.store(&[pointer, value], Some(space))?;
        self.effects += 1;

        Ok(())
    }

    fn lift_register(
        &mut self,
        id: PCodeLocationId,
        location: &PCodeLocation,
    ) -> Result<IlExprId, IlError> {
        if let Some(value) = self.register_reads.get(&id).copied() {
            return Ok(value);
        }

        let range = RegisterRange::new(location.offset(), usize::from(location.size()))?;
        let slice = self
            .register_bank
            .slice(range)?
            .ok_or_else(|| IlError::missing_component(PCodeIr::FORM, "register root"))?;
        let root = self.register_value(slice)?;
        let value = if slice.is_root() {
            root
        } else {
            self.buffer.apply(
                ECodeOpcode::Extract,
                slice.bits(),
                &[root],
                u64::from(slice.byte_offset()) * 8,
                None,
            )?
        };
        self.register_reads.insert(id, value);

        Ok(value)
    }

    fn register_value(&mut self, slice: RegisterSlice) -> Result<IlExprId, IlError> {
        if let Some(value) = self.register_values.get(&slice.root()).copied() {
            return Ok(value);
        }

        let value = self.buffer.read_register(slice.root(), slice.root_bits())?;
        self.register_values.insert(slice.root(), value);

        Ok(value)
    }

}
