use fugue_specs::Confidence;

use crate::ir::{
    Address, AddressTable, AddressWithContext, FunctionId, Switch, SwitchCase, SwitchEvidence,
    SwitchId, SwitchModel, SwitchProperties,
};

pub(crate) struct RecoveredSwitch {
    model: SwitchModel,
    cases: Vec<SwitchCase>,
    evidence: SwitchEvidence,
    properties: SwitchProperties,
    default: Option<AddressWithContext>,
}

impl RecoveredSwitch {
    pub(crate) fn new(
        model: SwitchModel,
        cases: Vec<SwitchCase>,
        evidence: SwitchEvidence,
        properties: SwitchProperties,
    ) -> Self {
        Self {
            model,
            cases,
            evidence,
            properties,
            default: None,
        }
    }

    pub(crate) fn with_default(mut self, default: AddressWithContext) -> Self {
        self.default = Some(default);
        self
    }

    pub(crate) fn cases(&self) -> &[SwitchCase] {
        &self.cases
    }

    pub(crate) fn confidence(&self) -> Confidence {
        self.evidence.confidence(self.properties)
    }

    pub(crate) fn is_guarded(&self) -> bool {
        self.evidence.contains(SwitchEvidence::GUARD_FOUND)
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
        let truncated = self.properties.contains(SwitchProperties::TRUNCATED);
        let partial = truncated && !self.evidence.contains(SwitchEvidence::GUARD_FOUND);
        let mut switch = Switch::new(id, branch, self.model).with_function(function);
        for case in self.cases {
            switch.add_case(case);
        }
        switch.set_evidence(self.evidence);
        if let Some(default) = self.default {
            switch.set_default_case(SwitchCase::new(default));
        }
        if truncated {
            switch.mark_truncated();
        }
        if partial {
            switch.mark_partial();
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
