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
                for (_, operation) in ir
                    .graph()
                    .ops_for_block(block, ir.ops())
                    .rev()
                {
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
mod test;
