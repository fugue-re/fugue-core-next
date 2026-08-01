use std::mem;

use super::super::change::ChangeKinds;
use super::super::{Analyser, AnalysisPhase, Priority};
use crate::ir::{AddressRange, AddressRangeSet};

pub(crate) struct ScheduledAnalyser {
    analyser: Box<dyn Analyser>,
    claimed: AddressRangeSet,
    max_attempts: usize,
    order: u32,
    phase: AnalysisPhase,
    priority: Priority,
    triggers: ChangeKinds,
}

impl ScheduledAnalyser {
    pub(crate) fn new(analyser: Box<dyn Analyser>) -> Self {
        let max_attempts = analyser.max_attempts();
        let phase = analyser.phase();
        let priority = analyser.priority();
        let triggers = analyser.triggers();

        Self {
            analyser,
            claimed: AddressRangeSet::new(),
            max_attempts,
            order: 0,
            phase,
            priority,
            triggers,
        }
    }

    pub(crate) fn analyser(&self) -> &dyn Analyser {
        self.analyser.as_ref()
    }

    pub(crate) fn analyser_mut(&mut self) -> &mut dyn Analyser {
        self.analyser.as_mut()
    }

    pub(crate) fn claim(&mut self, range: AddressRange) {
        self.claimed.insert_range(range);
    }

    pub(crate) fn clear_claimed(&mut self) {
        self.claimed = AddressRangeSet::new();
    }

    pub(crate) fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub(crate) fn order(&self) -> u32 {
        self.order
    }

    pub(crate) fn phase(&self) -> AnalysisPhase {
        self.phase
    }

    pub(crate) fn priority(&self) -> Priority {
        self.priority
    }

    pub(crate) fn retract_claimed(&mut self, range: AddressRange) {
        self.claimed.remove_range(range);
    }

    pub(crate) fn set_order(&mut self, order: u32) {
        self.order = order;
    }

    pub(crate) fn take_claimed(&mut self) -> AddressRangeSet {
        mem::take(&mut self.claimed)
    }

    pub(crate) fn triggers(&self) -> ChangeKinds {
        self.triggers
    }
}
