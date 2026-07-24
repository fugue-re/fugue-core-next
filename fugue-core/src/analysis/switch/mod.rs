use recovered::RecoveredSwitch;
use resolver::SwitchTargetResolver;

mod analysis;
mod idiom;
mod interval;
mod recovered;
mod resolver;

pub use analysis::SwitchRecovery;

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
