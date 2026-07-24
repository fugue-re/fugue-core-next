use crate::ir::{
    Address, AddressTable, AddressWithContext, FunctionId, IncompleteCodeBlockId,
    IncompleteFunction, Switch, SwitchCase, SwitchId, SwitchModel, SwitchProperties,
};
use crate::types::Confidence;

pub(crate) struct RecoveredSwitch {
    model: SwitchModel,
    cases: Vec<SwitchCase>,
    properties: SwitchProperties,
    default: Option<AddressWithContext>,
}

impl RecoveredSwitch {
    pub(crate) fn new(
        model: SwitchModel,
        cases: Vec<SwitchCase>,
        properties: SwitchProperties,
    ) -> Self {
        Self {
            model,
            cases,
            properties,
            default: None,
        }
    }

    pub(crate) fn with_default(mut self, default: AddressWithContext) -> Self {
        self.default = Some(default);
        self
    }

    pub(crate) fn infer_default_from_incoming(
        mut self,
        function: &IncompleteFunction,
        branch_block: IncompleteCodeBlockId,
    ) -> Self {
        if self.default.is_some() {
            return self;
        }
        let Some(branch) = function.block(branch_block) else {
            return self;
        };
        for predecessor in branch.predecessors().iter() {
            let Some(guard) = function.block(predecessor) else {
                continue;
            };
            let mut successors = guard.successors().iter();
            let (Some(first), Some(second), None) =
                (successors.next(), successors.next(), successors.next())
            else {
                continue;
            };
            let default = if first == branch_block && second != branch_block {
                second
            } else if second == branch_block && first != branch_block {
                first
            } else {
                continue;
            };
            let Some(block) = function.block(default) else {
                continue;
            };
            self.default = Some(AddressWithContext::new(
                block.address(),
                block.context().clone(),
            ));
            break;
        }
        self
    }

    pub(crate) fn cases(&self) -> &[SwitchCase] {
        &self.cases
    }

    pub(crate) fn confidence(&self) -> Confidence {
        self.properties.confidence()
    }

    pub(crate) fn is_guarded(&self) -> bool {
        self.properties.contains(SwitchProperties::GUARD_FOUND)
    }

    pub(crate) fn reconcile(self, candidate: Self) -> Option<Self> {
        if !self.has_same_layout(&candidate) {
            return None;
        }
        if candidate.cases.len() > self.cases.len() {
            Some(candidate)
        } else {
            Some(self)
        }
    }

    pub(crate) fn should_replace_with(&self, candidate: &Self) -> bool {
        if !self.has_same_layout(candidate) {
            return false;
        }
        match (self.is_guarded(), candidate.is_guarded()) {
            (false, true) => true,
            (true, false) => false,
            _ => candidate.cases.len() > self.cases.len(),
        }
    }

    pub(crate) fn into_switch(self, id: SwitchId, function: FunctionId, branch: Address) -> Switch {
        let mut switch = Switch::new(id, branch, self.model)
            .with_function(function)
            .with_properties(self.properties);
        for case in self.cases {
            switch.add_case(case);
        }
        if let Some(default) = self.default {
            switch.set_default_case(SwitchCase::new(default));
        }
        switch
    }

    fn has_same_layout(&self, candidate: &Self) -> bool {
        let same_table = |a: &AddressTable, b: &AddressTable| {
            a.address() == b.address()
                && a.element_size() == b.element_size()
                && a.shift() == b.shift()
        };
        match (&self.model, &candidate.model) {
            (SwitchModel::Absolute(a), SwitchModel::Absolute(b))
            | (SwitchModel::InlineBranchTable(a), SwitchModel::InlineBranchTable(b)) => {
                same_table(a, b)
            }
            (
                SwitchModel::OffsetRelative {
                    table: a,
                    base: a_base,
                    signed: a_signed,
                },
                SwitchModel::OffsetRelative {
                    table: b,
                    base: b_base,
                    signed: b_signed,
                },
            ) => same_table(a, b) && a_base == b_base && a_signed == b_signed,
            (
                SwitchModel::TwoLevel {
                    outer: a_outer,
                    inner: a_inner,
                },
                SwitchModel::TwoLevel {
                    outer: b_outer,
                    inner: b_inner,
                },
            ) => same_table(a_outer, b_outer) && same_table(a_inner, b_inner),
            (SwitchModel::Explicit, SwitchModel::Explicit) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::IncompleteCodeBlock;
    use crate::lifter::ContextSet;

    #[test]
    fn recovered_switch_infers_cfg_default_before_persistence() {
        let guard = Address::from(0x1000u64);
        let branch = Address::from(0x1010u64);
        let default = Address::from(0x1020u64);
        let mut function = IncompleteFunction::new(guard);
        let guard_block = function.push_block(IncompleteCodeBlock::new(
            guard,
            1,
            Vec::new(),
            ContextSet::default(),
        ));
        let branch_block = function.push_block(IncompleteCodeBlock::new(
            branch,
            1,
            Vec::new(),
            ContextSet::default(),
        ));
        let default_block = function.push_block(IncompleteCodeBlock::new(
            default,
            1,
            Vec::new(),
            ContextSet::default(),
        ));
        function.add_block_edge(guard_block, branch_block).unwrap();
        function.add_block_edge(guard_block, default_block).unwrap();

        let recovered =
            RecoveredSwitch::new(SwitchModel::Explicit, Vec::new(), SwitchProperties::empty())
                .infer_default_from_incoming(&function, branch_block)
                .into_switch(SwitchId::INVALID, FunctionId::INVALID, branch);

        assert_eq!(
            recovered.default_case().map(|case| case.target().address()),
            Some(default)
        );
    }
}
