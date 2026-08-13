use rustc_hash::{FxHashMap, FxHashSet};

use crate::il::common::{FlagId, IlArtefact, IlBlockId, IlValueId, RegisterId};
use crate::il::ecode::ssa::{
    ECodeSsaBlockArgInputs, ECodeSsaDomain, ECodeSsaIr, ECodeSsaLiveness, ECodeSsaOp,
};
use crate::il::mcode::disjoint_set::DisjointSet;
use crate::il::mcode::recovery::{MCodeStackModel, MCodeStackObjectId};
use crate::il::mcode::{MCodeVar, MCodeVarId, MCodeVarKind};

#[derive(Debug, Clone)]
pub(crate) struct MCodeVariableModel {
    variables: Vec<MCodeVar>,
    value_variables: FxHashMap<IlValueId, MCodeVarId>,
    stack_variables: Vec<MCodeVarId>,
}

impl MCodeVariableModel {
    pub(crate) fn new(ir: &ECodeSsaIr, stack: &MCodeStackModel) -> Self {
        let mut components = DisjointSet::new(ir.values().len());
        let mut transparent = DisjointSet::new(ir.values().len());

        let inputs = ir.analyse::<ECodeSsaBlockArgInputs>();
        for (argument, argument_inputs) in inputs.iter() {
            for &input in argument_inputs {
                components.union(argument.index(), input.index());
                if ir.value_domain(argument).is_none() && ir.value_domain(input).is_none() {
                    transparent.union(argument.index(), input.index());
                }
            }
        }

        Self::merge_derived_values(ir, &mut components, &mut transparent);

        let liveness = ir.analyse::<ECodeSsaLiveness>();
        let mut live = FxHashMap::<ECodeSsaDomain, FxHashSet<IlValueId>>::default();
        if ir.graph().blocks().is_empty() {
            for operation in ir.operations().iter().rev() {
                Self::merge_live_ranges(ir, operation, &mut live, &mut components);
            }
        } else {
            for block_index in 0..ir.graph().blocks().len() {
                let block =
                    IlBlockId::try_from_index(block_index).expect("block id is representable");
                live.clear();
                for &value in liveness.live_out(block) {
                    if let Some(domain) = ir
                        .value_domain(value)
                        .filter(ECodeSsaDomain::is_register_or_flag)
                    {
                        live.entry(domain).or_default().insert(value);
                    }
                }
                for (_, operation) in ir.operations_for_block(block).rev() {
                    Self::merge_live_ranges(ir, operation, &mut live, &mut components);
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
                Some(ECodeSsaDomain::Register(storage)) => {
                    (MCodeVarKind::Register, storage.value())
                }
                Some(ECodeSsaDomain::Flag(storage)) => (MCodeVarKind::Flag, storage.value()),
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

    fn merge_live_ranges(
        ir: &ECodeSsaIr,
        operation: &ECodeSsaOp,
        live: &mut FxHashMap<ECodeSsaDomain, FxHashSet<IlValueId>>,
        components: &mut DisjointSet,
    ) {
        if !operation.results().is_empty() {
            let result = IlValueId::try_from_index(operation.results().start())
                .expect("value id is representable");
            if let Some(domain) = ir.value_domain(result)
                && domain.is_register_or_flag()
            {
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
        }
        for &operand in ir.operation_operands_for(operation) {
            if let Some(domain) = ir.value_domain(operand)
                && domain.is_register_or_flag()
            {
                live.entry(domain).or_default().insert(operand);
            }
        }
    }

    fn merge_derived_values(
        ir: &ECodeSsaIr,
        components: &mut DisjointSet,
        transparent: &mut DisjointSet,
    ) {
        for operation in ir.operations() {
            let operands = ir.operation_operands_for(operation);
            for index in operation.results().start()..operation.results().end() {
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
        }

        let mut representatives = FxHashMap::<(usize, ECodeSsaDomain), IlValueId>::default();
        let mut merge_representative = |components: &mut DisjointSet,
                                        root: usize,
                                        domain: ECodeSsaDomain,
                                        value: IlValueId| {
            if let Some(&representative) = representatives.get(&(root, domain)) {
                components.union(representative.index(), value.index());
            } else {
                representatives.insert((root, domain), value);
            }
        };
        for operation in ir.operations() {
            let operands = ir.operation_operands_for(operation);
            for index in operation.results().start()..operation.results().end() {
                let result = IlValueId::try_from_index(index).expect("value id is representable");
                if let Some(domain) = ir
                    .value_domain(result)
                    .filter(ECodeSsaDomain::is_register_or_flag)
                {
                    for &operand in operands {
                        if ir
                            .value_domain(operand)
                            .filter(ECodeSsaDomain::is_register_or_flag)
                            == Some(domain)
                        {
                            components.union(result.index(), operand.index());
                        } else if ir.value_domain(operand).is_none() {
                            let root = transparent.find(operand.index());
                            merge_representative(components, root, domain, result);
                        }
                    }
                } else if ir.value_domain(result).is_none() {
                    let root = transparent.find(result.index());
                    for &operand in operands {
                        if let Some(domain) = ir
                            .value_domain(operand)
                            .filter(ECodeSsaDomain::is_register_or_flag)
                        {
                            merge_representative(components, root, domain, operand);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test;
