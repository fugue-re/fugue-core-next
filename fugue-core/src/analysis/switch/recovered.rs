use crate::ir::{
    Address, AddressTable, AddressWithContext, FunctionId, Switch, SwitchCase, SwitchId,
    SwitchModel, SwitchProperties,
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

    pub(crate) fn with_fallback_default(mut self, default: Option<AddressWithContext>) -> Self {
        if self.default.is_none() {
            self.default = default;
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
        Some(if self.should_replace_with(&candidate) {
            candidate
        } else {
            self
        })
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
            .with_cases(self.cases)
            .with_properties(self.properties);
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
    use crate::ir::{IncompleteCodeBlock, IncompleteFunction};
    use crate::lifter::ContextSet;

    fn recovered_with_cases(count: u64, properties: SwitchProperties) -> RecoveredSwitch {
        let cases = (0..count)
            .map(|address| SwitchCase::new(Address::from(address).into()))
            .collect();
        RecoveredSwitch::new(SwitchModel::Explicit, cases, properties)
    }

    #[test]
    fn guarded_recovery_wins_over_larger_unguarded_recovery() {
        let guarded = recovered_with_cases(2, SwitchProperties::GUARD_FOUND);
        let unguarded = recovered_with_cases(3, SwitchProperties::empty());

        let reconciled = guarded
            .reconcile(unguarded)
            .expect("explicit switch layouts are compatible");
        assert!(reconciled.is_guarded());
        assert_eq!(reconciled.cases().len(), 2);
    }

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
                .with_fallback_default(function.sibling_successor_from_incoming(branch_block))
                .into_switch(SwitchId::INVALID, FunctionId::INVALID, branch);

        assert_eq!(
            recovered.default_case().map(|case| case.target().address()),
            Some(default)
        );
    }
}
