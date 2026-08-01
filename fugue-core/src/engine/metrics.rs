use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
struct Counters {
    dispatches: AtomicU64,
    items_dispatched: AtomicU64,
    retries: AtomicU64,
    retries_exhausted: AtomicU64,
    causes_merged: AtomicU64,
    ranges_collapsed: AtomicU64,
    read_sets_collapsed: AtomicU64,
    dependency_reschedules: AtomicU64,
    admission_conflicts: AtomicU64,
    admission_resynchronisations: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct EngineMetrics {
    counters: Arc<Counters>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineMetricsSnapshot {
    dispatches: u64,
    items_dispatched: u64,
    retries: u64,
    retries_exhausted: u64,
    causes_merged: u64,
    ranges_collapsed: u64,
    read_sets_collapsed: u64,
    dependency_reschedules: u64,
    admission_conflicts: u64,
    admission_resynchronisations: u64,
}

impl EngineMetricsSnapshot {
    pub fn dispatches(&self) -> u64 {
        self.dispatches
    }

    pub fn items_dispatched(&self) -> u64 {
        self.items_dispatched
    }

    pub fn retries(&self) -> u64 {
        self.retries
    }

    pub fn retries_exhausted(&self) -> u64 {
        self.retries_exhausted
    }

    pub fn causes_merged(&self) -> u64 {
        self.causes_merged
    }

    pub fn ranges_collapsed(&self) -> u64 {
        self.ranges_collapsed
    }

    pub fn read_sets_collapsed(&self) -> u64 {
        self.read_sets_collapsed
    }

    pub fn dependency_reschedules(&self) -> u64 {
        self.dependency_reschedules
    }

    pub fn admission_conflicts(&self) -> u64 {
        self.admission_conflicts
    }

    pub fn admission_resynchronisations(&self) -> u64 {
        self.admission_resynchronisations
    }
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_dispatch(&self, items: usize) {
        self.counters.dispatches.fetch_add(1, Ordering::Relaxed);
        self.counters
            .items_dispatched
            .fetch_add(items as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_retry(&self) {
        self.counters.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_retry_exhausted(&self) {
        self.counters
            .retries_exhausted
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_causes_merged(&self) {
        self.counters.causes_merged.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ranges_collapsed(&self) {
        self.counters
            .ranges_collapsed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_read_set_collapsed(&self) {
        self.counters
            .read_sets_collapsed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dependency_reschedule(&self) {
        self.counters
            .dependency_reschedules
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_admission_conflict(&self) {
        self.counters
            .admission_conflicts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_admission_resynchronisation(&self) {
        self.counters
            .admission_resynchronisations
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> EngineMetricsSnapshot {
        EngineMetricsSnapshot {
            dispatches: self.counters.dispatches.load(Ordering::Relaxed),
            items_dispatched: self.counters.items_dispatched.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
            retries_exhausted: self.counters.retries_exhausted.load(Ordering::Relaxed),
            causes_merged: self.counters.causes_merged.load(Ordering::Relaxed),
            ranges_collapsed: self.counters.ranges_collapsed.load(Ordering::Relaxed),
            read_sets_collapsed: self.counters.read_sets_collapsed.load(Ordering::Relaxed),
            dependency_reschedules: self.counters.dependency_reschedules.load(Ordering::Relaxed),
            admission_conflicts: self.counters.admission_conflicts.load(Ordering::Relaxed),
            admission_resynchronisations: self
                .counters
                .admission_resynchronisations
                .load(Ordering::Relaxed),
        }
    }
}
