use rustc_hash::{FxHashMap, FxHashSet};

use crate::il::common::{FlagId, IlArtefact, IlBlockId, IlValueId, RegisterId};
use crate::il::ecode::{ECodeBlockArgInputs, ECodeDomain, ECodeIr, ECodeLiveness, ECodeOp};
use crate::il::mcode::disjoint_set::DisjointSet;
use crate::il::mcode::recovery::{MCodeStackModel, MCodeStackObjectId};
use crate::il::mcode::{MCodeVar, MCodeVarId, MCodeVarKind};

fn merge_live_ranges(
    ir: &ECodeIr,
    operation: &ECodeOp,
    live: &mut FxHashMap<ECodeDomain, FxHashSet<IlValueId>>,
    components: &mut DisjointSet,
) {
    let result = (!operation.results().is_empty()).then(|| {
        IlValueId::try_from_index(operation.results().start()).expect("value id is representable")
    });
    let defined_domain = result.and_then(|value| {
        ir.value_domain(value)
            .filter(ECodeDomain::is_register_or_flag)
            .map(|domain| (value, domain))
    });
    if let Some((result, domain)) = defined_domain {
        if let Some(values) = live.get(&domain) {
            for &other in values {
                if other != result {
                    components.union(result.index(), other.index());
                }
            }
        }
        if let Some(values) = live.get_mut(&domain) {
            values.remove(&result);
        }
    }
    for &operand in ir.op_operands_for(operation) {
        let Some(domain) = ir
            .value_domain(operand)
            .filter(ECodeDomain::is_register_or_flag)
        else {
            continue;
        };
        live.entry(domain).or_default().insert(operand);
    }
}

fn merge_derived_values(ir: &ECodeIr, components: &mut DisjointSet, transparent: &mut DisjointSet) {
    for (operation, index) in ir.ops().iter().flat_map(|operation| {
        (operation.results().start()..operation.results().end())
            .map(move |index| (operation, index))
    }) {
        let operands = ir.op_operands_for(operation);
        let result = IlValueId::try_from_index(index).expect("value id is representable");
        if ir.value_domain(result).is_some() {
            continue;
        }
        for &operand in operands {
            if ir.value_domain(operand).is_none() {
                transparent.union(result.index(), operand.index());
            }
        }
    }

    let mut representatives = FxHashMap::<(usize, ECodeDomain), IlValueId>::default();
    let mut merge_representative =
        |components: &mut DisjointSet, root: usize, domain: ECodeDomain, value: IlValueId| {
            if let Some(&representative) = representatives.get(&(root, domain)) {
                components.union(representative.index(), value.index());
            } else {
                representatives.insert((root, domain), value);
            }
        };
    for (operation, index) in ir.ops().iter().flat_map(|operation| {
        (operation.results().start()..operation.results().end())
            .map(move |index| (operation, index))
    }) {
        let operands = ir.op_operands_for(operation);
        let result = IlValueId::try_from_index(index).expect("value id is representable");
        let result_domain = ir.value_domain(result);
        match result_domain.filter(ECodeDomain::is_register_or_flag) {
            Some(domain) => {
                for &operand in operands {
                    match ir
                        .value_domain(operand)
                        .filter(ECodeDomain::is_register_or_flag)
                    {
                        Some(operand_domain) if operand_domain == domain => {
                            components.union(result.index(), operand.index());
                        }
                        None if ir.value_domain(operand).is_none() => {
                            let root = transparent.find(operand.index());
                            merge_representative(components, root, domain, result);
                        }
                        _ => {}
                    }
                }
            }
            None if result_domain.is_none() => {
                let root = transparent.find(result.index());
                for &operand in operands {
                    if let Some(domain) = ir
                        .value_domain(operand)
                        .filter(ECodeDomain::is_register_or_flag)
                    {
                        merge_representative(components, root, domain, operand);
                    }
                }
            }
            None => {}
        }
    }
}

#[derive(Debug)]
pub(crate) struct MCodeVariableModel {
    variables: Vec<MCodeVar>,
    value_variables: FxHashMap<IlValueId, MCodeVarId>,
    stack_variables: Vec<MCodeVarId>,
}

impl MCodeVariableModel {
    pub(crate) fn new(ir: &ECodeIr, stack: &MCodeStackModel) -> Self {
        let mut components = DisjointSet::new(ir.values().len());
        let mut transparent = DisjointSet::new(ir.values().len());

        let inputs = ir.analyse::<ECodeBlockArgInputs>();
        for (arg, arg_inputs) in inputs.iter() {
            for &input in arg_inputs {
                components.union(arg.index(), input.index());
                if ir.value_domain(arg).is_none() && ir.value_domain(input).is_none() {
                    transparent.union(arg.index(), input.index());
                }
            }
        }

        merge_derived_values(ir, &mut components, &mut transparent);

        let liveness = ir.analyse::<ECodeLiveness>();
        let mut live = FxHashMap::<ECodeDomain, FxHashSet<IlValueId>>::default();
        if ir.graph().blocks().is_empty() {
            for operation in ir.ops().iter().rev() {
                merge_live_ranges(ir, operation, &mut live, &mut components);
            }
        } else {
            for block_index in 0..ir.graph().blocks().len() {
                let block =
                    IlBlockId::try_from_index(block_index).expect("block id is representable");
                live.clear();
                for &value in liveness.live_out(block) {
                    if let Some(domain) = ir
                        .value_domain(value)
                        .filter(ECodeDomain::is_register_or_flag)
                    {
                        live.entry(domain).or_default().insert(value);
                    }
                }
                for (_, operation) in ir.graph().ops_for_block(block, ir.ops()).rev() {
                    merge_live_ranges(ir, operation, &mut live, &mut components);
                }
            }
        }

        let mut variables = Vec::new();
        let mut value_variables = FxHashMap::default();
        let mut component_variable = FxHashMap::<usize, MCodeVarId>::default();
        let mut splits = FxHashMap::<(MCodeVarKind, u64), u32>::default();

        for index in 0..ir.values().len() {
            let value = IlValueId::try_from_index(index).expect("value id is representable");
            let (kind, storage) = match ir.value_domain(value) {
                Some(ECodeDomain::Register(storage)) => (MCodeVarKind::Register, storage.value()),
                Some(ECodeDomain::Flag(storage)) => (MCodeVarKind::Flag, storage.value()),
                _ => continue,
            };
            let root = components.find(index);
            let variable = *component_variable.entry(root).or_insert_with(|| {
                let split = splits.entry((kind, storage)).or_insert(0);
                let identity = match kind {
                    MCodeVarKind::Flag => MCodeVar::flag(FlagId::new(storage), *split),
                    MCodeVarKind::Register => MCodeVar::register(RegisterId::new(storage), *split),
                    MCodeVarKind::Stack => unreachable!(),
                };
                *split += 1;
                let id = MCodeVarId::try_from_index(variables.len())
                    .expect("variable id is representable");
                variables.push(identity);
                id
            });
            value_variables.insert(value, variable);
        }

        let mut stack_variables = Vec::with_capacity(stack.objects().len());
        for object in stack.objects() {
            let id =
                MCodeVarId::try_from_index(variables.len()).expect("variable id is representable");
            variables.push(MCodeVar::stack(object.start()));
            stack_variables.push(id);
        }

        Self {
            variables,
            value_variables,
            stack_variables,
        }
    }

    pub(crate) fn variables(&self) -> &[MCodeVar] {
        &self.variables
    }

    pub(crate) fn variable_for_value(&self, value: IlValueId) -> Option<MCodeVarId> {
        self.value_variables.get(&value).copied()
    }

    pub(crate) fn stack_variable(&self, object: MCodeStackObjectId) -> Option<MCodeVarId> {
        self.stack_variables.get(object.index()).copied()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{
        IlBlock, IlBlockId, IlBlockProperties, IlEdgeKinds, IlError, IlGraph, IlIndexRange,
        IlMetadata, IlValueId, RegisterId,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeOpSpec, ECodeOpcode};
    use crate::il::mcode::recovery::MCodeStackModel;
    use crate::ir::FunctionId;
    use crate::storage::segments::space::AddressSpaceId;

    const REGISTER: u64 = 0x10;

    fn emit_value(
        builder: &mut ECodeBuilder,
        spec: ECodeOpSpec,
        operands: impl IntoIterator<Item = IlValueId>,
    ) -> Result<IlValueId, IlError> {
        let (_, results) = builder.emitter().emit(spec, operands, 1)?;
        IlValueId::try_from_index(results.start())
    }

    fn builder() -> ECodeBuilder {
        ECodeBuilder::new(
            IlMetadata::new(FunctionId::default(), 0),
            IlGraph::default(),
        )
    }

    fn register_definition(builder: &mut ECodeBuilder) -> IlValueId {
        let id = emit_value(builder, ECodeOpSpec::new(ECodeOpcode::Undefined, 64), []).unwrap();
        builder
            .emitter()
            .set_value_domain(id, ECodeDomain::Register(RegisterId::new(REGISTER)))
            .unwrap();
        id
    }

    fn table(ir: &ECodeIr) -> MCodeVariableModel {
        let stack = MCodeStackModel::new(ir, RegisterId::new(0xffff), []);
        MCodeVariableModel::new(ir, &stack)
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

        fn constant(&mut self, value: u64) -> IlValueId {
            let id = emit_value(
                &mut self.builder,
                ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(value),
                [],
            )
            .unwrap();
            self.operations += 1;
            id
        }

        fn unary(&mut self, opcode: ECodeOpcode, source: IlValueId, register: bool) -> IlValueId {
            let id = emit_value(
                &mut self.builder,
                ECodeOpSpec::new(opcode, 64).with_immediate(REGISTER),
                [source],
            )
            .unwrap();
            if register {
                self.builder
                    .emitter()
                    .set_value_domain(id, ECodeDomain::Register(RegisterId::new(REGISTER)))
                    .unwrap();
            }
            self.operations += 1;
            id
        }

        fn binary(&mut self, opcode: ECodeOpcode, left: IlValueId, right: IlValueId) -> IlValueId {
            let id = emit_value(
                &mut self.builder,
                ECodeOpSpec::new(opcode, 64),
                [left, right],
            )
            .unwrap();
            self.operations += 1;
            id
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

    fn branching_ir(reverse: bool) -> ECodeIr {
        let left = IlBlockId::try_from_index(1).unwrap();
        let right = IlBlockId::try_from_index(2).unwrap();
        let mut builder = builder();
        register_definition(&mut builder);
        register_definition(&mut builder);
        let (successors, kinds) = if reverse {
            (
                vec![right, left],
                vec![IlEdgeKinds::TAKEN, IlEdgeKinds::FALL_THROUGH],
            )
        } else {
            (
                vec![left, right],
                vec![IlEdgeKinds::FALL_THROUGH, IlEdgeKinds::TAKEN],
            )
        };
        builder.set_graph(IlGraph::new(
            vec![
                IlBlock::new(
                    IlIndexRange::EMPTY,
                    IlIndexRange::new(0, 2).unwrap(),
                    IlBlockProperties::ENTRY,
                ),
                IlBlock::new(
                    IlIndexRange::new(0, 1).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
                IlBlock::new(
                    IlIndexRange::new(1, 2).unwrap(),
                    IlIndexRange::EMPTY,
                    IlBlockProperties::EXIT,
                ),
            ],
            successors,
            kinds,
        ));
        builder.build_unchecked()
    }

    #[test]
    fn disjoint_register_definitions_split_by_lifetime() {
        let mut builder = builder();
        let first = register_definition(&mut builder);
        let second = register_definition(&mut builder);

        let ir = builder.build_unchecked();
        let table = table(&ir);

        let first_variable = table.variable_for_value(first).unwrap();
        let second_variable = table.variable_for_value(second).unwrap();
        assert_ne!(first_variable, second_variable);

        let first = table.variables()[first_variable.index()];
        let second = table.variables()[second_variable.index()];
        assert_eq!(first.kind(), MCodeVarKind::Register);
        assert_eq!(first.register_id(), Some(RegisterId::new(REGISTER)));
        assert_eq!(second.register_id(), Some(RegisterId::new(REGISTER)));
        assert_ne!(first.index(), second.index());
    }

    #[test]
    fn a_phi_connected_web_is_one_variable() {
        let entry = IlBlockId::try_from_index(0).unwrap();
        let merge = IlBlockId::try_from_index(1).unwrap();
        let mut builder = builder();

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
            vec![merge],
            vec![IlEdgeKinds::UNCONDITIONAL],
        ));

        let _ = entry;
        let definition = register_definition(&mut builder);
        let arg = builder.emitter().emit_block_arg(merge, 64).unwrap();
        builder
            .emitter()
            .set_value_domain(arg, ECodeDomain::Register(RegisterId::new(REGISTER)))
            .unwrap();
        builder.emitter().emit_edge_args([definition]).unwrap();

        let ir = builder.build_unchecked();
        let table = table(&ir);

        assert_eq!(
            table.variable_for_value(definition),
            table.variable_for_value(arg)
        );
    }

    #[test]
    fn stack_objects_become_stack_variables() {
        let mut builder = builder();
        let sp = {
            let id = emit_value(
                &mut builder,
                ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
                [],
            )
            .unwrap();
            builder
                .emitter()
                .set_value_domain(id, ECodeDomain::Register(RegisterId::new(0x20)))
                .unwrap();
            id
        };
        let size = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(0x10),
            [],
        )
        .unwrap();
        let frame = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Sub, 64),
            [sp, size],
        )
        .unwrap();
        let value = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(1),
            [],
        )
        .unwrap();
        let space = AddressSpaceId::new(0);
        let memory = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 0),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(memory, ECodeDomain::Memory(space))
            .unwrap();
        builder
            .emitter()
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Store, 0).with_address_space(space),
                [frame, value, memory],
                0,
            )
            .unwrap();

        let ir = builder.build_unchecked();
        let stack = MCodeStackModel::new(&ir, RegisterId::new(0x20), []);
        let table = MCodeVariableModel::new(&ir, &stack);

        let variable = table
            .stack_variable(MCodeStackObjectId::from_index(0))
            .expect("one stack object");
        assert_eq!(
            table.variables()[variable.index()].kind(),
            MCodeVarKind::Stack
        );
        assert_eq!(
            table.variables()[variable.index()].stack_offset(),
            Some(-0x10)
        );
    }

    #[test]
    fn an_overlapping_redefinition_is_one_variable() {
        let mut function = Function::new();
        let first_value = function.constant(1);
        let first = function.unary(ECodeOpcode::WriteRegister, first_value, true);
        let second_value = function.constant(2);
        let second = function.unary(ECodeOpcode::WriteRegister, second_value, true);
        function.binary(ECodeOpcode::Add, first, second);
        let ir = function.finish();

        let table = table(&ir);

        assert_eq!(
            table.variable_for_value(first),
            table.variable_for_value(second)
        );
        let variable = table.variable_for_value(first).unwrap();
        assert_eq!(table.variables()[variable.index()].index(), 0);
    }

    #[test]
    fn an_overlapping_linear_redefinition_is_one_variable() {
        let mut function = Function::new();
        let first_value = function.constant(1);
        let first = function.unary(ECodeOpcode::WriteRegister, first_value, true);
        let second_value = function.constant(2);
        let second = function.unary(ECodeOpcode::WriteRegister, second_value, true);
        function.binary(ECodeOpcode::Add, first, second);
        let ir = function.finish_linear();

        let table = table(&ir);

        assert_eq!(
            table.variable_for_value(first),
            table.variable_for_value(second)
        );
    }

    #[test]
    fn a_partial_update_stays_one_variable() {
        let mut function = Function::new();
        let initial = function.constant(0x1122_3344);
        let whole = function.unary(ECodeOpcode::WriteRegister, initial, true);
        let byte = function.constant(0xff);
        let inserted = function.binary(ECodeOpcode::Insert, whole, byte);
        let updated = function.unary(ECodeOpcode::WriteRegister, inserted, true);
        let ir = function.finish();

        let table = table(&ir);

        assert_eq!(
            table.variable_for_value(whole),
            table.variable_for_value(updated)
        );
        let variable = table.variable_for_value(whole).unwrap();
        assert_eq!(table.variables()[variable.index()].index(), 0);
    }

    #[test]
    fn proven_disjoint_redefinitions_split_into_distinct_variables() {
        let mut function = Function::new();
        let first_value = function.constant(1);
        let first = function.unary(ECodeOpcode::WriteRegister, first_value, true);
        function.unary(ECodeOpcode::Copy, first, false);
        let second_value = function.constant(2);
        let second = function.unary(ECodeOpcode::WriteRegister, second_value, true);
        function.unary(ECodeOpcode::Copy, second, false);
        let ir = function.finish();

        let table = table(&ir);

        let first_variable = table.variable_for_value(first).unwrap();
        let second_variable = table.variable_for_value(second).unwrap();
        assert_ne!(first_variable, second_variable);
        assert_eq!(
            table.variables()[first_variable.index()].register_id(),
            Some(RegisterId::new(REGISTER))
        );
        assert_ne!(
            table.variables()[first_variable.index()].index(),
            table.variables()[second_variable.index()].index()
        );
    }

    #[test]
    fn shared_expression_ancestry_is_coalesced_once() {
        let mut function = Function::new();
        let initial = function.constant(1);
        let initial = function.unary(ECodeOpcode::WriteRegister, initial, true);
        let mut shared = initial;
        for _ in 0..2048 {
            shared = function.unary(ECodeOpcode::Copy, shared, false);
        }
        let mut definitions = Vec::new();
        for _ in 0..2048 {
            definitions.push(function.unary(ECodeOpcode::WriteRegister, shared, true));
        }
        let ir = function.finish();

        let table = table(&ir);
        let expected = table.variable_for_value(initial);

        assert!(
            definitions
                .iter()
                .all(|&definition| table.variable_for_value(definition) == expected)
        );
    }

    #[test]
    fn successor_order_does_not_rename_variables() {
        let forward = table(&branching_ir(false));
        let reverse = table(&branching_ir(true));

        assert_eq!(forward.variables(), reverse.variables());
    }
}
