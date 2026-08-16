use rustc_hash::FxHashMap;

use crate::il::mcode::recovery::{MCodeStackModel, MCodeStackObjectId, MCodeVariableModel};
use crate::il::mcode::{MCodeVar, MCodeVarId};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MCodeAliasOverride {
    Aliased,
    Unaliased,
}

#[derive(Debug, Default)]
pub(crate) struct MCodeAliasOverrides(FxHashMap<MCodeVar, MCodeAliasOverride>);

impl MCodeAliasOverrides {
    pub(crate) fn insert(&mut self, variable: MCodeVar, override_: MCodeAliasOverride) {
        self.0.insert(variable, override_);
    }

    pub(crate) fn remove(&mut self, variable: MCodeVar) {
        self.0.remove(&variable);
    }

    fn get(&self, variable: &MCodeVar) -> Option<MCodeAliasOverride> {
        self.0.get(variable).copied()
    }
}

#[derive(Debug)]
pub(crate) struct MCodeAliasSet {
    aliased: Vec<MCodeVarId>,
}

impl MCodeAliasSet {
    pub(crate) fn new<'a>(
        stack: &MCodeStackModel,
        variables: &MCodeVariableModel,
        overrides: impl Into<Option<&'a MCodeAliasOverrides>>,
    ) -> Self {
        let overrides = overrides.into();
        let mut aliased = Vec::new();
        for (index, object) in stack.objects().iter().enumerate() {
            let object_id = MCodeStackObjectId::from_index(index);
            let Some(id) = variables.stack_variable(object_id) else {
                continue;
            };
            let variable = variables.variables()[id.index()];
            let is_aliased = match overrides.and_then(|overrides| overrides.get(&variable)) {
                Some(MCodeAliasOverride::Aliased) => true,
                Some(MCodeAliasOverride::Unaliased) => false,
                None => object.address_taken(),
            };
            if is_aliased {
                aliased.push(id);
            }
        }
        aliased.sort_unstable();
        aliased.dedup();

        Self { aliased }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = MCodeVarId> + '_ {
        self.aliased.iter().copied()
    }

    pub(crate) fn contains(&self, variable: MCodeVarId) -> bool {
        self.aliased.binary_search(&variable).is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::analysis::control::CancellationToken;
    use crate::il::common::{IlGraph, IlMetadata, RegisterId};
    use crate::il::ecode::test::emit_value;
    use crate::il::ecode::{ECodeBuilder, ECodeDomain, ECodeIr, ECodeOpSpec, ECodeOpcode};
    use crate::il::mcode::MCodeVarKind;
    use crate::il::mcode::recovery::MCodeStackModel;
    use crate::ir::FunctionId;

    const STACK_POINTER: u64 = 0x20;

    fn escaping_frame() -> (ECodeIr, MCodeStackModel, MCodeVariableModel) {
        let mut builder = ECodeBuilder::new(
            IlMetadata::new(FunctionId::default(), 0),
            IlGraph::default(),
        );

        let sp = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
            [],
        )
        .unwrap();
        builder
            .emitter()
            .set_value_domain(sp, ECodeDomain::Register(RegisterId::new(STACK_POINTER)))
            .unwrap();

        let size = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(0x20),
            [],
        )
        .unwrap();

        let frame = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Sub, 64),
            [sp, size],
        )
        .unwrap();

        let junk = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Undefined, 64),
            [],
        )
        .unwrap();

        let _ = emit_value(
            &mut builder,
            ECodeOpSpec::new(ECodeOpcode::Add, 64),
            [frame, junk],
        )
        .unwrap();

        let ir = builder
            .build_unchecked(&CancellationToken::default())
            .unwrap();
        let stack = MCodeStackModel::new(&ir, RegisterId::new(STACK_POINTER), []);
        let variables = MCodeVariableModel::new(&ir, &stack);
        (ir, stack, variables)
    }

    fn taken_stack_variable(stack: &MCodeStackModel, variables: &MCodeVariableModel) -> MCodeVarId {
        let index = stack
            .objects()
            .iter()
            .position(|object| object.address_taken())
            .expect("an address-taken object");
        variables
            .stack_variable(MCodeStackObjectId::from_index(index))
            .expect("a stack variable")
    }

    #[test]
    fn an_address_taken_object_is_aliased_by_default() {
        let (_, stack, variables) = escaping_frame();
        let aliased = taken_stack_variable(&stack, &variables);

        let set = MCodeAliasSet::new(&stack, &variables, None);

        assert!(set.contains(aliased));
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![aliased]);
    }

    #[test]
    fn an_unaliased_override_clears_an_object() {
        let (_, stack, variables) = escaping_frame();
        let aliased = taken_stack_variable(&stack, &variables);
        let identity = variables.variables()[aliased.index()];
        assert_eq!(identity.kind(), MCodeVarKind::Stack);

        let mut overrides = MCodeAliasOverrides::default();
        overrides.insert(identity, MCodeAliasOverride::Unaliased);
        let set = MCodeAliasSet::new(&stack, &variables, Some(&overrides));

        assert!(!set.contains(aliased));
        assert!(set.iter().next().is_none());
    }
}
