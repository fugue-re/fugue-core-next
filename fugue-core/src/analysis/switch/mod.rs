use fugue_bv::BitVec;
use fugue_specs::Confidence;

use crate::arch::Arch;
use crate::ir::{
    Address, AddressWithContext, FunctionId, RawAddress, Switch, SwitchCase, SwitchEvidence,
    SwitchId, SwitchModel, SwitchProvenance,
};
use crate::lifter::{ContextSet, LiftingContext};
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentReader;
use crate::storage::segments::space::AddressSpaceId;

mod analysis;
pub use analysis::SwitchRecovery;

mod idiom;
mod slice;

#[derive(Debug, Clone, Copy)]
pub struct SwitchRecoveryConfig {
    max_cases: u32,
    max_element_size: u32,
    max_trace_depth: u32,
    max_trace_steps: usize,
}

impl Default for SwitchRecoveryConfig {
    fn default() -> Self {
        Self {
            max_cases: 4096,
            max_element_size: 8,
            max_trace_depth: 256,
            max_trace_steps: 1 << 20,
        }
    }
}

impl SwitchRecoveryConfig {
    pub fn max_cases(&self) -> u32 {
        self.max_cases
    }

    pub fn set_max_cases(&mut self, max_cases: u32) {
        self.max_cases = max_cases;
    }

    pub fn with_max_cases(mut self, max_cases: u32) -> Self {
        self.set_max_cases(max_cases);
        self
    }

    pub fn max_element_size(&self) -> u32 {
        self.max_element_size
    }

    pub fn set_max_element_size(&mut self, max_element_size: u32) {
        self.max_element_size = max_element_size;
    }

    pub fn with_max_element_size(mut self, max_element_size: u32) -> Self {
        self.set_max_element_size(max_element_size);
        self
    }

    pub fn max_trace_depth(&self) -> u32 {
        self.max_trace_depth
    }

    pub fn set_max_trace_depth(&mut self, max_trace_depth: u32) {
        self.max_trace_depth = max_trace_depth;
    }

    pub fn with_max_trace_depth(mut self, max_trace_depth: u32) -> Self {
        self.set_max_trace_depth(max_trace_depth);
        self
    }

    pub fn max_trace_steps(&self) -> usize {
        self.max_trace_steps
    }

    pub fn set_max_trace_steps(&mut self, max_trace_steps: usize) {
        self.max_trace_steps = max_trace_steps;
    }

    pub fn with_max_trace_steps(mut self, max_trace_steps: usize) -> Self {
        self.set_max_trace_steps(max_trace_steps);
        self
    }
}

pub(crate) struct RecoveredSwitch {
    model: SwitchModel,
    cases: Vec<SwitchCase>,
    confidence: Confidence,
    evidence: SwitchEvidence,
    default: Option<AddressWithContext>,
}

impl RecoveredSwitch {
    pub fn new(
        model: SwitchModel,
        cases: Vec<SwitchCase>,
        confidence: Confidence,
        evidence: SwitchEvidence,
    ) -> Self {
        Self {
            model,
            cases,
            confidence,
            evidence,
            default: None,
        }
    }

    pub fn with_default(mut self, default: AddressWithContext) -> Self {
        self.default = Some(default);
        self
    }

    pub fn model(&self) -> &SwitchModel {
        &self.model
    }

    pub fn cases(&self) -> &[SwitchCase] {
        &self.cases
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn evidence(&self) -> SwitchEvidence {
        self.evidence
    }

    pub fn is_partial(&self) -> bool {
        self.evidence.contains(SwitchEvidence::TRUNCATED)
            && !self.evidence.contains(SwitchEvidence::GUARD_FOUND)
    }

    pub fn into_switch(self, id: SwitchId, function: FunctionId, branch: Address) -> Switch {
        let partial = self.is_partial();
        let truncated = self.evidence.contains(SwitchEvidence::TRUNCATED);
        let mut switch = Switch::new(id, branch, self.model).with_function(function);
        for case in self.cases {
            switch.add_case(case);
        }
        switch.set_provenance(SwitchProvenance::new(self.confidence, self.evidence));
        if let Some(default) = self.default {
            switch.set_default_case(SwitchCase::new(default));
        }
        if partial {
            switch.mark_partial();
        }
        if truncated {
            switch.mark_truncated();
        }
        switch
    }
}

pub(crate) struct SwitchTargetResolver<'a> {
    arch: &'a Arch,
    reader: SegmentReader<'a>,
    space: AddressSpaceId,
}

impl<'a> SwitchTargetResolver<'a> {
    pub(crate) fn new(arch: &'a Arch, segments: &'a SegmentStorage, space: AddressSpaceId) -> Self {
        Self {
            arch,
            reader: SegmentReader::new(segments),
            space,
        }
    }

    pub(crate) fn resolve(
        &mut self,
        value: &BitVec,
        context: &LiftingContext,
    ) -> Option<AddressWithContext> {
        let (canonical, context) = self
            .arch
            .canonicalise_address_with(RawAddress::from(value.to_u64()?), context)?;
        self.resolved(canonical, context)
    }

    pub(crate) fn resolve_address(
        &mut self,
        value: RawAddress,
        context: &LiftingContext,
    ) -> Option<AddressWithContext> {
        let (canonical, context) = self.arch.canonicalise_address_with(value, context)?;
        self.resolved(canonical, context)
    }

    fn resolved(
        &mut self,
        canonical: RawAddress,
        context: ContextSet,
    ) -> Option<AddressWithContext> {
        let address = Address::new(self.space, canonical);
        let executable = self
            .reader
            .properties(address)
            .is_some_and(|properties| properties.is_executable());
        executable.then(|| AddressWithContext::new(address, context))
    }
}
