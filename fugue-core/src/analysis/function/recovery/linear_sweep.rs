const DEFAULT_MIN_ZERO_FILL_BYTES: usize = 16;
const DEFAULT_MAX_TRIAL_INSNS: usize = 16;
const DEFAULT_MIN_POST_BOUNDARY_INSNS: usize = 4;
const DEFAULT_MIN_ENTRY_MARKER_INSNS: usize = 2;
const DEFAULT_MIN_CALL_TARGET_INSNS: usize = 2;
const DEFAULT_CALL_TARGET_CORROBORATION_INSNS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinearSweepConfig {
    min_zero_fill_bytes: usize,
    max_trial_insns: usize,
    min_post_boundary_insns: usize,
    min_entry_marker_insns: usize,
    min_call_target_insns: usize,
    call_target_corroboration_insns: usize,
}

impl Default for LinearSweepConfig {
    fn default() -> Self {
        Self {
            min_zero_fill_bytes: DEFAULT_MIN_ZERO_FILL_BYTES,
            max_trial_insns: DEFAULT_MAX_TRIAL_INSNS,
            min_post_boundary_insns: DEFAULT_MIN_POST_BOUNDARY_INSNS,
            min_entry_marker_insns: DEFAULT_MIN_ENTRY_MARKER_INSNS,
            min_call_target_insns: DEFAULT_MIN_CALL_TARGET_INSNS,
            call_target_corroboration_insns: DEFAULT_CALL_TARGET_CORROBORATION_INSNS,
        }
    }
}

impl LinearSweepConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn min_zero_fill_bytes(&self) -> usize {
        self.min_zero_fill_bytes
    }

    pub fn set_min_zero_fill_bytes(&mut self, size: usize) {
        self.min_zero_fill_bytes = size.max(1);
    }

    pub fn with_min_zero_fill_bytes(mut self, size: usize) -> Self {
        self.set_min_zero_fill_bytes(size);
        self
    }

    pub fn max_trial_insns(&self) -> usize {
        self.max_trial_insns
    }

    pub fn set_max_trial_insns(&mut self, count: usize) {
        self.max_trial_insns = count.max(1);
    }

    pub fn with_max_trial_insns(mut self, count: usize) -> Self {
        self.set_max_trial_insns(count);
        self
    }

    pub fn min_post_boundary_insns(&self) -> usize {
        self.min_post_boundary_insns
    }

    pub fn set_min_post_boundary_insns(&mut self, count: usize) {
        self.min_post_boundary_insns = count.max(1);
    }

    pub fn with_min_post_boundary_insns(mut self, count: usize) -> Self {
        self.set_min_post_boundary_insns(count);
        self
    }

    pub fn min_entry_marker_insns(&self) -> usize {
        self.min_entry_marker_insns
    }

    pub fn set_min_entry_marker_insns(&mut self, count: usize) {
        self.min_entry_marker_insns = count.max(1);
    }

    pub fn with_min_entry_marker_insns(mut self, count: usize) -> Self {
        self.set_min_entry_marker_insns(count);
        self
    }

    pub fn min_call_target_insns(&self) -> usize {
        self.min_call_target_insns
    }

    pub fn set_min_call_target_insns(&mut self, count: usize) {
        self.min_call_target_insns = count.max(1);
    }

    pub fn with_min_call_target_insns(mut self, count: usize) -> Self {
        self.set_min_call_target_insns(count);
        self
    }

    pub fn call_target_corroboration_insns(&self) -> usize {
        self.call_target_corroboration_insns
    }

    pub fn set_call_target_corroboration_insns(&mut self, count: usize) {
        self.call_target_corroboration_insns = count.max(1);
    }

    pub fn with_call_target_corroboration_insns(mut self, count: usize) -> Self {
        self.set_call_target_corroboration_insns(count);
        self
    }
}
