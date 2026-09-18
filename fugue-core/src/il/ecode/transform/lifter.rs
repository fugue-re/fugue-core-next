use rustc_hash::FxHashMap;

use super::graph::{PCodeToECodeGraphMapper, remap_source_spans};
use super::ssa::{PCodeToECodeSsaLifter, PCodeToECodeSsaScratch};
use super::state::ECodeLiftState;
use crate::arch::Arch;
use crate::il::common::{
    FlagId, IlArtefact, IlError, IlExprId, IlGraph, IlIndexMapper, IlMetadata, RegisterBank,
    RegisterId, RegisterRange, RegisterSlice,
};
use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeOpcode};
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
    platform: &'a Platform,
    source: &'a PCodeIr,
    graph_mapper: &'b mut PCodeToECodeGraphMapper,
    state: ECodeLiftState,
    register_bank: RegisterBank,
    flags: FxHashMap<PCodeLocation, FlagId>,
    values: FxHashMap<(PCodeLocationId, LocationRole), IlExprId>,
    register_values: FxHashMap<RegisterId, IlExprId>,
    register_reads: FxHashMap<PCodeLocationId, IlExprId>,
    flag_values: FxHashMap<FlagId, IlExprId>,
    lift_scratch: &'b mut PCodeToECodeLiftScratch,
    ssa_scratch: &'b mut PCodeToECodeSsaScratch,
    space: Option<AddressSpaceId>,
    effects: usize,
}

impl<'a, 'b> PCodeToECodeLifter<'a, 'b> {
    pub(crate) fn new(
        arch: &'a Arch,
        platform: &'a Platform,
        source: &'a PCodeIr,
        graph_mapper: &'b mut PCodeToECodeGraphMapper,
        lift_scratch: &'b mut PCodeToECodeLiftScratch,
        ssa_scratch: &'b mut PCodeToECodeSsaScratch,
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
            platform,
            source,
            graph_mapper,
            state: ECodeLiftState::default(),
            register_bank,
            flags,
            values: FxHashMap::default(),
            register_values: FxHashMap::default(),
            register_reads: FxHashMap::default(),
            flag_values: FxHashMap::default(),
            lift_scratch,
            ssa_scratch,
            space: None,
            effects: 0,
        })
    }

    fn location(&self, id: PCodeLocationId) -> &PCodeLocation {
        self.source
            .location(id)
            .expect("location id is within the location pool")
    }

    pub(crate) fn lift(mut self) -> Result<ECodeIr, IlError> {
        let operation_map = self.lift_ops()?;
        let graph = self.graph_mapper.remap(self.source, &operation_map)?;
        let parent_spans = operation_map.parent_spans()?;
        let source_spans = remap_source_spans(self.source, &operation_map)?;
        let metadata = IlMetadata::new(
            self.source.metadata().function(),
            self.source.metadata().input_revision(),
        );
        let builder = ECodeBuilder::new(metadata, IlGraph::default());

        PCodeToECodeSsaLifter::new(
            self.state,
            graph,
            source_spans,
            parent_spans,
            builder,
            self.ssa_scratch,
        )
        .lift()
    }

    fn lift_ops(&mut self) -> Result<IlIndexMapper, IlError> {
        let mut operation_map = Vec::with_capacity(self.source.ops().len() + 1);
        let mut source_span = 0usize;

        for (index, operation) in self.source.ops().iter().enumerate() {
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
            .call_preserved_registers(self.platform.compiler_spec_id())?;
        self.state
            .set_call_preserved_registers(call_preserved_registers);

        Ok(operation_map)
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

        self.lift_scratch.intrinsic_args.clear();
        for operand in self.source.op_operands_for(operation) {
            let location = self.location(*operand);
            self.lift_scratch.intrinsic_args.push(Varnode::new(
                location.lifter_space().value(),
                location.offset(),
                location.size(),
            ));
        }
        let is_trap = self.arch.is_trap_intrinsic(
            u16::try_from(operation.immediate())
                .expect("PCode user-op identifier originated as u16"),
            &self.lift_scratch.intrinsic_args,
        );

        if is_trap {
            self.state.trap(intrinsic, operation.address_space())?;
        } else {
            self.lift_operand_values(operation, None)?;
            self.state.intrinsic(
                intrinsic,
                &self.lift_scratch.operands,
                operation.address_space(),
            )?;
        }
        self.effects += 1;

        Ok(())
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
            self.lift_scratch.operands.clear();
            self.lift_scratch.operands.push(source);
        } else {
            let address_operand = (opcode == PCodeOpcode::Load).then_some(0);
            self.lift_operand_values(operation, address_operand)?;
        }
        let expression = self.state.apply(
            ecode_opcode(opcode)?,
            output_width,
            &self.lift_scratch.operands,
            immediate,
            operation.address_space(),
        )?;

        self.assign_output(output, expression)
    }

    fn assign_output(&mut self, id: PCodeLocationId, value: IlExprId) -> Result<(), IlError> {
        let location = *self.location(id);
        if let Some(flag) = self.flags.get(&location).copied() {
            self.flag_values.insert(flag, value);
            self.state.write_flag(flag, value)?;
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
            self.state.apply(
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
        self.state.write_register(slice.root(), value)?;
        self.effects += 1;

        Ok(())
    }

    fn lift_store(&mut self, operation: &PCodeOp) -> Result<(), IlError> {
        self.lift_operand_values(operation, Some(0))?;
        self.state
            .store(&self.lift_scratch.operands, operation.address_space())?;
        self.effects += 1;

        Ok(())
    }

    fn lift_direct_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeOpcode,
    ) -> Result<(), IlError> {
        self.lift_scratch.operands.clear();
        for operand_index in 1..self.source.op_operands_for(operation).len() {
            let operand = self.source.op_operands_for(operation)[operand_index];
            let operand = self.lift_location(operand, LocationRole::Value)?;
            self.lift_scratch.operands.push(operand);
        }
        let target = self
            .source
            .target(
                operation
                    .target()
                    .expect("direct flow operation has a target identifier"),
            )
            .expect("direct flow target is within the target pool");

        self.state
            .direct_flow(opcode, target.address(), &self.lift_scratch.operands)?;
        self.effects += 1;

        Ok(())
    }

    fn lift_indirect_flow(
        &mut self,
        operation: &PCodeOp,
        opcode: ECodeOpcode,
    ) -> Result<(), IlError> {
        self.lift_operand_values(operation, Some(0))?;
        self.state.indirect_flow(
            opcode,
            &self.lift_scratch.operands,
            operation.address_space(),
        )?;
        self.effects += 1;

        Ok(())
    }

    fn lift_operand_values(
        &mut self,
        operation: &PCodeOp,
        address_operand: Option<usize>,
    ) -> Result<(), IlError> {
        self.lift_scratch.operands.clear();
        for operand_index in 0..self.source.op_operands_for(operation).len() {
            let operand = self.source.op_operands_for(operation)[operand_index];
            let role = if address_operand == Some(operand_index) {
                LocationRole::Address
            } else {
                LocationRole::Value
            };
            let operand = self.lift_location(operand, role)?;
            self.lift_scratch.operands.push(operand);
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
                LocationRole::Address => self.state.address(location.bits(), location.offset())?,
                LocationRole::Value => self.state.constant(location.bits(), location.offset())?,
            }
        } else if let Some(flag) = self.flags.get(&location).copied() {
            if let Some(value) = self.flag_values.get(&flag).copied() {
                return Ok(value);
            }
            let value = self.state.read_flag(flag, location.bits())?;
            self.flag_values.insert(flag, value);
            return Ok(value);
        } else if location.is_register() {
            return self.lift_register(id, &location);
        } else if location.lifter_space().value() == self.arch.language().default_space() {
            return self.lift_memory_read(&location);
        } else {
            self.state
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
            .state
            .address(self.arch.language().address_bits(), location.offset())?;
        self.state.apply(
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
            .state
            .address(self.arch.language().address_bits(), location.offset())?;
        self.state.store(&[pointer, value], Some(space))?;
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
            self.state.apply(
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

        let value = self.state.read_register(slice.root(), slice.root_bits())?;
        self.register_values.insert(slice.root(), value);

        Ok(value)
    }
}

#[cfg(test)]
mod test {
    use super::super::PCodeToECode;
    use super::super::state::{ECodeLiftEffect, ECodeLiftExpr, ECodeLiftExprKind, ECodeLiftState};
    use super::*;
    use crate::arch::Arch;
    use crate::il::common::{
        IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlExprId, IlIndexRange, IlMetadata,
        IlParentSpan, IlSourceSpan,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeOpcode};
    use crate::il::pcode::{
        PCodeBuilder, PCodeLifterSpaceHandle, PCodeLocation, PCodeLocationProperties, PCodeOpSpec,
        PCodeOpcode,
    };
    use crate::ir::{Address, FunctionId};
    use crate::lifter::{Language, Varnode, resolve_language};
    use crate::platform::Platform;
    use crate::storage::segments::space::AddressSpaceId;

    fn language() -> &'static Language {
        resolve_language("x86:LE:64").expect("test language should resolve")
    }

    fn arch() -> Arch {
        Arch::new(language())
    }

    fn platform() -> Platform {
        arch().platform()
    }

    struct ECodeLiftStateFixture {
        metadata: IlMetadata,
        graph: IlGraph,
        parent_spans: Vec<IlParentSpan>,
        source_spans: Vec<IlSourceSpan>,
        state: ECodeLiftState,
    }

    impl ECodeLiftStateFixture {
        fn metadata(&self) -> &IlMetadata {
            &self.metadata
        }

        fn graph(&self) -> &IlGraph {
            &self.graph
        }

        fn parent_spans(&self) -> &[IlParentSpan] {
            &self.parent_spans
        }

        fn expressions(&self) -> &[ECodeLiftExpr] {
            self.state.expressions()
        }

        fn ops(&self) -> &[ECodeLiftEffect] {
            self.state.ops()
        }

        fn op_operands_for(&self, operation: &ECodeLiftEffect) -> &[IlExprId] {
            self.state.op_operands_for(operation)
        }

        fn build(self) -> Result<ECodeIr, IlError> {
            let builder = ECodeBuilder::new(self.metadata, IlGraph::default());
            PCodeToECodeSsaLifter::new(
                self.state,
                self.graph,
                self.source_spans,
                self.parent_spans,
                builder,
                &mut PCodeToECodeSsaScratch::default(),
            )
            .lift()
        }
    }

    fn lift_fixture(
        transform: &mut PCodeToECode,
        source: &PCodeIr,
        arch: &Arch,
        platform: &Platform,
    ) -> Result<ECodeLiftStateFixture, IlError> {
        let metadata = IlMetadata::new(
            source.metadata().function(),
            source.metadata().input_revision(),
        );
        let mut lifter = PCodeToECodeLifter::new(
            arch,
            platform,
            source,
            &mut transform.graph_mapper,
            &mut transform.lift_scratch,
            &mut transform.ssa_scratch,
        )?;
        let operation_map = lifter.lift_ops()?;
        let graph = lifter.graph_mapper.remap(source, &operation_map)?;
        let parent_spans = operation_map.parent_spans()?;
        let source_spans = remap_source_spans(source, &operation_map)?;

        Ok(ECodeLiftStateFixture {
            metadata,
            graph,
            parent_spans,
            source_spans,
            state: lifter.state,
        })
    }

    #[test]
    fn empty_pcode_lifts_to_empty_ecode() {
        let pcode_metadata = IlMetadata::new(FunctionId::default(), 11);
        let source = PCodeBuilder::new(pcode_metadata, IlGraph::default())
            .build()
            .unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.metadata().input_revision().value(), 11);
        assert!(lifted.ops().is_empty());
    }

    #[test]
    fn empty_source_span_does_not_desynchronise_instruction_cache_clears() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let constant = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                7,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        for offset in 0..3 {
            let output = builder
                .emitter()
                .intern_location(PCodeLocation::new(
                    PCodeLifterSpaceHandle::new(1),
                    offset,
                    8,
                    PCodeLocationProperties::UNIQUE,
                ))
                .unwrap();
            builder
                .emitter()
                .emit(
                    PCodeOpSpec::new(PCodeOpcode::Copy),
                    Some(output),
                    [constant],
                )
                .unwrap();
        }
        builder.set_source_spans(vec![
            IlSourceSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                Address::from(0x1000u64),
                0,
                1,
            ),
            IlSourceSpan::new(
                IlIndexRange::new(1, 1).unwrap(),
                Address::from(0x1001u64),
                0,
                1,
            ),
            IlSourceSpan::new(
                IlIndexRange::new(1, 2).unwrap(),
                Address::from(0x1002u64),
                0,
                1,
            ),
            IlSourceSpan::new(
                IlIndexRange::new(2, 3).unwrap(),
                Address::from(0x1003u64),
                0,
                1,
            ),
        ]);
        let source = builder.build().unwrap();

        let lifted =
            lift_fixture(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();
        assert_eq!(
            lifted
                .expressions()
                .iter()
                .filter(
                    |expression| expression.kind() == ECodeLiftExprKind::Op(ECodeOpcode::Constant)
                )
                .count(),
            3
        );
    }

    #[test]
    fn copy_pcode_lifts_to_ecode_write() {
        let source = copy_source();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(
            lifted.expressions()[1].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Copy)
        );
        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(lifted.ops()[0].immediate(), 8);
        assert_eq!(
            lifted.parent_spans(),
            &[IlParentSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(0, 1).unwrap(),
            )]
        );
    }

    #[test]
    fn large_subpiece_offset_is_not_truncated_to_operand_width() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1234,
                64,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let offset = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                32,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                32,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Subpiece),
                Some(output),
                [input, offset],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_fixture(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        let extract = &lifted.expressions()[1];
        assert_eq!(extract.kind(), ECodeLiftExprKind::Op(ECodeOpcode::Extract));
        assert_eq!(extract.immediate(), 256);
        assert_eq!(extract.operands().len(), 1);
    }

    #[test]
    fn partial_registers_share_one_full_width_domain() {
        let language = language();
        let rax = language.register_by_name("RAX").expect("RAX should exist");
        let al = language.register_by_name("AL").expect("AL should exist");
        let ah = language.register_by_name("AH").expect("AH should exist");
        let ax = language.register_by_name("AX").expect("AX should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0x12, 1),
            ))
            .unwrap();
        let al = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &al))
            .unwrap();
        let ah = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &ah))
            .unwrap();
        let ax = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &ax))
            .unwrap();
        let high = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, 1),
            ))
            .unwrap();
        let word = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, 2),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(ah), [constant])
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(high), [al])
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(word), [ax])
            .unwrap();
        let source = builder.build().unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();
        let register_reads = lifted
            .expressions()
            .iter()
            .filter(|expression| expression.kind() == ECodeLiftExprKind::ReadRegister)
            .collect::<Vec<_>>();
        let extracts = lifted
            .expressions()
            .iter()
            .filter(|expression| expression.kind() == ECodeLiftExprKind::Op(ECodeOpcode::Extract))
            .collect::<Vec<_>>();
        let insert = lifted
            .expressions()
            .iter()
            .find(|expression| expression.kind() == ECodeLiftExprKind::Op(ECodeOpcode::Insert))
            .expect("partial write should insert into the root");

        assert_eq!(register_reads.len(), 1);
        assert_eq!(register_reads[0].immediate(), rax.offset());
        assert_eq!(register_reads[0].width(), 64);
        assert_eq!(insert.width(), 64);
        assert_eq!(insert.immediate(), 8);
        assert_eq!(
            extracts
                .iter()
                .map(|extract| extract.width())
                .collect::<Vec<_>>(),
            vec![8, 16]
        );
        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::WriteRegister);
        assert_eq!(lifted.ops()[0].immediate(), rax.offset());

        let ir = lifted.build().unwrap();
        ir.verify().unwrap();
    }

    #[test]
    fn architectural_flags_use_flag_operations() {
        let language = language();
        let cf = language.register_by_name("CF").expect("CF should exist");
        let wide_register = Varnode::new(cf.space(), cf.offset(), cf.size + 1);
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let flag = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let read_before = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, cf.size),
            ))
            .unwrap();
        let read_after = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, cf.size),
            ))
            .unwrap();
        let wide_register = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &wide_register))
            .unwrap();
        let wide_constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0, cf.size + 1),
            ))
            .unwrap();
        let flag_constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(read_before),
                [flag],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(wide_register),
                [wide_constant],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(read_after),
                [flag],
            )
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(flag),
                [flag_constant],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_fixture(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert_eq!(
            lifted
                .expressions()
                .iter()
                .filter(|expression| {
                    expression.kind() == ECodeLiftExprKind::ReadFlag
                        && expression.immediate() == cf.offset()
                })
                .count(),
            2
        );
        assert!(
            lifted.ops().iter().any(|op| {
                op.opcode() == ECodeOpcode::WriteFlag && op.immediate() == cf.offset()
            })
        );
        assert!(
            !lifted
                .expressions()
                .iter()
                .any(|expression| expression.kind() == ECodeLiftExprKind::ReadRegister)
        );
    }

    #[test]
    fn unresolved_unique_input_lifts_to_undefined() {
        let language = language();
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x100, 8),
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::new(language.unique_space(), 0x200, 8),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_fixture(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert_eq!(
            lifted.expressions()[0].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Undefined)
        );
    }

    #[test]
    fn trap_intrinsic_lifts_to_trap_op() {
        let language = language();
        let trap = language
            .user_op_by_name("invalidInstructionException")
            .expect("x86 trap intrinsic should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(u32::from(trap)),
                None,
                [],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_fixture(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();

        assert!(lifted.expressions().is_empty());
        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Trap);
        assert_eq!(lifted.ops()[0].immediate(), u64::from(trap));
    }

    #[test]
    fn unique_output_pcode_does_not_lift_to_register_write() {
        let source = unique_copy_source();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert!(lifted.ops().is_empty());
        assert!(lifted.parent_spans().is_empty());
    }

    #[test]
    fn user_op_result_preserves_operands() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(7),
                Some(output),
                [input],
            )
            .unwrap();
        let source = builder.build().unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.expressions().len(), 2);
        assert_eq!(
            lifted.expressions()[1].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::IntrinsicResult)
        );
        assert_eq!(lifted.expressions()[1].operands().len(), 1);
    }

    #[test]
    fn store_pcode_lifts_to_ecode_store_with_fugue_space() {
        let source = store_source();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Store);
        let operands = lifted.op_operands_for(&lifted.ops()[0]);
        assert_eq!(
            lifted.expressions()[operands[0].index()].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Address)
        );
        assert_eq!(
            lifted.expressions()[operands[1].index()].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Constant)
        );
        assert_eq!(
            lifted.ops()[0].address_space(),
            Some(AddressSpaceId::new(7))
        );
    }

    #[test]
    fn constant_cache_distinguishes_address_and_value_roles() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let constant = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Store).with_address_space(AddressSpaceId::new(7)),
                None,
                [constant, constant],
            )
            .unwrap();
        let source = builder.build().unwrap();

        let lifted =
            lift_fixture(&mut PCodeToECode::default(), &source, &arch(), &platform()).unwrap();
        let operands = lifted.op_operands_for(&lifted.ops()[0]);

        assert_ne!(operands[0], operands[1]);
        assert_eq!(
            lifted.expressions()[operands[0].index()].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Address)
        );
        assert_eq!(
            lifted.expressions()[operands[1].index()].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Constant)
        );
    }

    #[test]
    fn branch_pcode_lifts_to_ecode_branch_with_target() {
        let target = Address::new(AddressSpaceId::new(3), 0x2000u64);
        let source = branch_source(target);
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Branch);
        assert_eq!(lifted.ops()[0].address(), Some(target));
    }

    #[test]
    fn indirect_branch_preserves_recovered_successors() {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let target = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::IBranch).with_address_space(AddressSpaceId::new(3)),
                None,
                [target],
            )
            .unwrap();
        builder.set_graph(IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::new(0, 1).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            vec![IlBlockId::try_from_index(1).unwrap()],
            vec![IlEdgeKinds::UNCONDITIONAL; 1],
        ));
        let source = builder.build().unwrap();
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();
        let entry = &lifted.graph().blocks()[0];

        assert_eq!(
            entry.successors().slice(lifted.graph().successors()),
            &[IlBlockId::try_from_index(1).unwrap()]
        );
        assert!(!entry.is_exit());
    }

    #[test]
    fn return_pcode_lifts_to_ecode_return_with_fugue_space() {
        let source = return_source(AddressSpaceId::new(9));
        let mut transform = PCodeToECode::default();

        let lifted = lift_fixture(&mut transform, &source, &arch(), &platform()).unwrap();

        assert_eq!(lifted.ops().len(), 1);
        assert_eq!(lifted.ops()[0].opcode(), ECodeOpcode::Return);
        let target = lifted.op_operands_for(&lifted.ops()[0])[0];
        assert_eq!(
            lifted.expressions()[target.index()].kind(),
            ECodeLiftExprKind::Op(ECodeOpcode::Address)
        );
        assert_eq!(
            lifted.ops()[0].address_space(),
            Some(AddressSpaceId::new(9))
        );
    }

    #[test]
    fn concrete_lifter_emits_each_effect_class() {
        let sources = [
            copy_source(),
            unique_copy_source(),
            flag_source(),
            store_source(),
            branch_source(Address::new(AddressSpaceId::new(3), 0x2000u64)),
            return_source(AddressSpaceId::new(9)),
            trap_source(),
            intrinsic_source(),
        ];
        let mut seen = Vec::new();
        for source in &sources {
            let lifted =
                lift_fixture(&mut PCodeToECode::default(), source, &arch(), &platform()).unwrap();
            seen.extend(lifted.ops().iter().map(ECodeLiftEffect::opcode));
        }

        for opcode in [
            ECodeOpcode::Branch,
            ECodeOpcode::Intrinsic,
            ECodeOpcode::Return,
            ECodeOpcode::Store,
            ECodeOpcode::Trap,
            ECodeOpcode::WriteFlag,
            ECodeOpcode::WriteRegister,
        ] {
            assert!(seen.contains(&opcode), "{opcode:?} is not exercised");
        }
    }

    fn pcode_metadata() -> IlMetadata {
        IlMetadata::new(FunctionId::default(), 11)
    }

    fn flag_source() -> PCodeIr {
        let language = language();
        let cf = language.register_by_name("CF").expect("CF should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let flag = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(language, &cf))
            .unwrap();
        let flag_constant = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(1, cf.size),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Copy),
                Some(flag),
                [flag_constant],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn trap_source() -> PCodeIr {
        let language = language();
        let trap = language
            .user_op_by_name("invalidInstructionException")
            .expect("x86 trap intrinsic should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(u32::from(trap)),
                None,
                [],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn intrinsic_source() -> PCodeIr {
        let language = language();
        let swi = language
            .user_op_by_name("swi")
            .expect("x86 software-interrupt intrinsic should exist");
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let arg = builder
            .emitter()
            .intern_location(PCodeLocation::from_varnode(
                language,
                &Varnode::constant(0x80, 8),
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::UserOp).with_immediate(u32::from(swi)),
                None,
                [arg],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                8,
                8,
                PCodeLocationProperties::REGISTER,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();

        builder.build().unwrap()
    }

    fn unique_copy_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let input = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                1,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let output = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(2),
                8,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .unwrap();

        builder.build().unwrap()
    }

    fn store_source() -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let offset = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let value = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0xff,
                1,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Store).with_address_space(AddressSpaceId::new(7)),
                None,
                [offset, value],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn branch_source(target: Address) -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let target_location = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                target.offset(),
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        let target = builder.emitter().emit_target(target.into()).unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Branch).with_target(target),
                None,
                [target_location],
            )
            .unwrap();

        builder.build().unwrap()
    }

    fn return_source(space: AddressSpaceId) -> PCodeIr {
        let mut builder = PCodeBuilder::new(pcode_metadata(), IlGraph::default());
        let target = builder
            .emitter()
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                0x1000,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .unwrap();
        builder
            .emitter()
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Return).with_address_space(space),
                None,
                [target],
            )
            .unwrap();

        builder.build().unwrap()
    }
}
