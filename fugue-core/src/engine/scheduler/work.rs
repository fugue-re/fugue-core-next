use std::collections::BTreeMap;
use std::mem;

use smallvec::{IntoIter, SmallVec};

use super::super::{AnalysisPhase, Priority, WorkCause};
use crate::ir::{Address, AddressRange, AddressRangeSet, ProblemScope, RawAddress};
use crate::storage::segments::space::AddressSpaceId;

pub(crate) const MAX_WORK_ITEMS_PER_ANALYSER: usize = 4096;
pub(crate) const MAX_WORK_ITEM_CAUSES: usize = 256;
pub(crate) const WORK_SLICE_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unknown_lints, sorted_enum_variants)]
pub(crate) enum Degradation {
    CausesMerged,
    RangesCollapsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DegradationEvent {
    kind: Degradation,
    scope: ProblemScope,
}

impl DegradationEvent {
    pub(crate) fn new(kind: Degradation, scope: ProblemScope) -> Self {
        Self { kind, scope }
    }

    pub(crate) fn kind(&self) -> Degradation {
        self.kind
    }

    pub(crate) fn scope(&self) -> ProblemScope {
        self.scope
    }
}

#[derive(Debug, Default)]
pub(crate) struct DegradationReport {
    events: SmallVec<[DegradationEvent; 2]>,
}

impl DegradationReport {
    pub(crate) fn push(&mut self, event: DegradationEvent) {
        if let Some(existing) = self
            .events
            .iter_mut()
            .find(|existing| existing.kind == event.kind)
        {
            existing.scope = existing.scope.covering(event.scope);
        } else {
            self.events.push(event);
        }
    }

    fn extend(&mut self, other: Self) {
        for event in other.events {
            self.push(event);
        }
    }
}

impl IntoIterator for DegradationReport {
    type IntoIter = IntoIter<[DegradationEvent; 2]>;
    type Item = DegradationEvent;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(unknown_lints, sorted_enum_variants)]
enum WorkKind {
    Region,
    Continuation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct WorkKey {
    phase: AnalysisPhase,
    address: Option<Address>,
    priority: Priority,
    analyser_order: u32,
    kind: WorkKind,
    end: RawAddress,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkItem {
    analyser: usize,
    analyser_order: u32,
    phase: AnalysisPhase,
    priority: Priority,
    range: Option<AddressRange>,
    causes: SmallVec<[WorkCause; 2]>,
    attempts: u8,
    kind: WorkKind,
}

pub(crate) type WorkBatch = SmallVec<[WorkItem; 8]>;

impl WorkItem {
    pub(crate) fn analyser(&self) -> usize {
        self.analyser
    }

    pub(crate) fn phase(&self) -> AnalysisPhase {
        self.phase
    }

    pub(crate) fn range(&self) -> Option<AddressRange> {
        self.range
    }

    pub(crate) fn causes(&self) -> &[WorkCause] {
        &self.causes
    }

    pub(crate) fn is_continuation(&self) -> bool {
        self.kind == WorkKind::Continuation
    }

    pub(crate) fn attempts(&self) -> u8 {
        self.attempts
    }

    pub(crate) fn record_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    fn regions(&self) -> AddressRangeSet {
        let mut regions = AddressRangeSet::new();
        if let Some(range) = self.range {
            regions.insert_range(range);
        }
        regions
    }

    fn key(&self) -> WorkKey {
        WorkKey {
            phase: self.phase,
            address: self.range.map(|range| range.start_address()),
            priority: self.priority,
            analyser_order: self.analyser_order,
            kind: self.kind,
            end: self.range.map_or(0u64.into(), |range| range.end()),
        }
    }

    fn absorb(&mut self, causes: &[WorkCause]) -> bool {
        let mut merged = false;

        for cause in causes {
            if self.causes.iter().any(|existing| existing == cause) {
                continue;
            }

            if self.causes.len() >= MAX_WORK_ITEM_CAUSES {
                if let Some(last) = self.causes.last_mut() {
                    last.coarsen(cause);
                }
                merged = true;
                continue;
            }

            self.causes.push(cause.clone());
        }

        merged
    }

    fn has_same_causes(&self, other: &Self) -> bool {
        self.causes.len() == other.causes.len()
            && self.causes.iter().all(|cause| other.causes.contains(cause))
    }

    fn with_range(&self, range: AddressRange) -> Self {
        Self {
            range: Some(range),
            ..self.clone()
        }
    }

    fn cost(&self) -> u64 {
        self.range.map_or(1, |range| range.size())
    }

    fn scope(&self) -> ProblemScope {
        self.range
            .map(ProblemScope::Range)
            .unwrap_or(ProblemScope::Global)
    }
}

#[derive(Default)]
pub(crate) struct AnalysisWorkQueue {
    items: BTreeMap<WorkKey, WorkItem>,
    locations: Vec<BTreeMap<(Option<AddressRange>, WorkKind), WorkKey>>,
    degradations: DegradationReport,
}

impl AnalysisWorkQueue {
    pub(crate) fn with_analysers(count: usize) -> Self {
        let mut locations = Vec::with_capacity(count);
        locations.resize_with(count, BTreeMap::new);

        Self {
            items: BTreeMap::new(),
            locations,
            degradations: DegradationReport::default(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn pending_for(&self, analyser: usize) -> AddressRangeSet {
        let mut pending = AddressRangeSet::new();
        let Some(locations) = self.locations.get(analyser) else {
            return pending;
        };

        for (range, _) in locations.keys() {
            if let Some(range) = range {
                pending.insert_range(*range);
            }
        }
        pending
    }

    pub(crate) fn has_pending_for(&self, analyser: usize) -> bool {
        self.locations
            .get(analyser)
            .is_some_and(|locations| !locations.is_empty())
    }

    pub(crate) fn schedule(
        &mut self,
        analyser: usize,
        analyser_order: u32,
        phase: AnalysisPhase,
        priority: Priority,
        regions: &AddressRangeSet,
        cause: impl Fn(Option<AddressRange>) -> WorkCause,
    ) -> DegradationReport {
        let mut degradations = DegradationReport::default();

        for range in regions
            .ranges()
            .map(Some)
            .chain(regions.is_empty().then_some(None))
        {
            let mut causes = SmallVec::new();
            causes.push(cause(range));
            let item = WorkItem {
                analyser,
                analyser_order,
                phase,
                priority,
                range,
                causes,
                attempts: 0,
                kind: WorkKind::Region,
            };

            degradations.extend(self.insert(item));
        }

        degradations
    }

    pub(crate) fn requeue(&mut self, item: WorkItem) -> DegradationReport {
        self.insert(item)
    }

    pub(crate) fn requeue_continuation(&mut self, items: WorkBatch) -> DegradationReport {
        let mut degradations = DegradationReport::default();

        for mut item in items {
            item.kind = WorkKind::Continuation;
            degradations.extend(self.insert(item));
        }

        degradations
    }

    fn insert(&mut self, item: WorkItem) -> DegradationReport {
        let analyser = item.analyser;
        let range = item.range;
        let location = (range, item.kind);
        let locations = self
            .locations
            .get_mut(analyser)
            .expect("scheduled analyser must have a queue index");

        if let Some(existing_key) = locations.get(&location).copied()
            && let Some(mut existing) = self.items.remove(&existing_key)
        {
            let merged = existing.absorb(&item.causes);
            existing.attempts = existing.attempts.max(item.attempts);
            existing.priority = existing.priority.min(item.priority);
            let key = existing.key();
            let replaced = self.items.insert(key, existing);
            assert!(
                replaced.is_none(),
                "promoted work must retain a unique queue key"
            );
            locations.insert(location, key);
            let mut degradations = DegradationReport::default();
            if merged {
                degradations.push(DegradationEvent::new(
                    Degradation::CausesMerged,
                    item.scope(),
                ));
            }
            return degradations;
        }

        self.insert_distinct(item);

        if self.locations[analyser].len() > MAX_WORK_ITEMS_PER_ANALYSER {
            return self.collapse(analyser);
        }

        DegradationReport::default()
    }

    fn insert_distinct(&mut self, item: WorkItem) {
        let analyser = item.analyser;
        let range = item.range;
        let location = (range, item.kind);
        let key = item.key();

        let previous_item = self.items.insert(key, item);
        let previous_location = self.locations[analyser].insert(location, key);
        assert!(
            previous_item.is_none() && previous_location.is_none(),
            "distinct work must have a unique queue key and location"
        );
    }

    fn collapse(&mut self, analyser: usize) -> DegradationReport {
        let locations = mem::take(
            self.locations
                .get_mut(analyser)
                .expect("scheduled analyser must have a queue index"),
        );
        let mut collapsed =
            BTreeMap::<(Option<AddressSpaceId>, WorkKind), (WorkItem, usize, bool)>::new();

        for (_, key) in locations {
            let item = self
                .items
                .remove(&key)
                .expect("queue location must name a work item");

            let group = (item.range.map(|range| range.space()), item.kind);
            match collapsed.get_mut(&group) {
                Some((current, count, causes_merged)) => {
                    *causes_merged |= !current.has_same_causes(&item);
                    *causes_merged |= current.absorb(&item.causes);
                    *count += 1;
                    current.attempts = current.attempts.max(item.attempts);
                    current.priority = current.priority.min(item.priority);
                    if let (Some(current_range), Some(item_range)) =
                        (current.range.as_mut(), item.range)
                    {
                        *current_range = AddressRange::new(
                            current_range.space(),
                            current_range.start().min(item_range.start()),
                            current_range.end().max(item_range.end()),
                        );
                    }
                }
                None => {
                    collapsed.insert(group, (item, 1, false));
                }
            }
        }

        let mut degradations = DegradationReport::default();
        for (_, (item, count, causes_merged)) in collapsed {
            let scope = item.scope();
            if causes_merged {
                degradations.push(DegradationEvent::new(Degradation::CausesMerged, scope));
            }
            if count > 1 {
                degradations.push(DegradationEvent::new(Degradation::RangesCollapsed, scope));
            }
            self.insert_distinct(item);
        }

        degradations
    }

    pub(crate) fn pop_batch(&mut self, budget: u64, max_items: usize) -> WorkBatch {
        let mut batch = WorkBatch::new();
        let Some(first) = self.pop(budget) else {
            return batch;
        };

        let analyser = first.analyser;
        let phase = first.phase;
        let kind = first.kind;
        let mut spent = first.cost();
        batch.push(first);

        while batch.len() < max_items && spent < budget {
            let Some(key) = self.items.keys().next().copied() else {
                break;
            };
            let Some(candidate) = self.items.get(&key) else {
                break;
            };
            if candidate.analyser != analyser || candidate.phase != phase || candidate.kind != kind
            {
                break;
            }

            let Some(next) = self.pop(budget - spent) else {
                break;
            };
            spent += next.cost();
            batch.push(next);
        }

        batch
    }

    pub(crate) fn pop(&mut self, budget: u64) -> Option<WorkItem> {
        if budget == 0 {
            return None;
        }

        let key = *self.items.keys().next()?;
        let mut item = self.items.remove(&key)?;
        self.locations[item.analyser].remove(&(item.range, item.kind));

        if item.range.is_some_and(|range| range.size() > budget) {
            let range = item.range.expect("checked as present");
            let space = range.space();
            let start = range.start();
            let split = start + (budget - 1);
            let remainder = item.with_range(AddressRange::new(space, split + 1u64, range.end()));
            item.range = Some(AddressRange::new(space, start, split));
            let degradations = self.insert(remainder);
            self.degradations.extend(degradations);
        }

        Some(item)
    }

    pub(crate) fn cancel(
        &mut self,
        phases: &[AnalysisPhase],
        region: &AddressRangeSet,
    ) -> DegradationReport {
        let affected = self
            .items
            .iter()
            .filter(|(_, item)| phases.contains(&item.phase))
            .filter(|(_, item)| {
                item.range
                    .is_some_and(|range| region.intersects_range(&range))
            })
            .map(|(key, _)| *key)
            .collect::<SmallVec<[_; 8]>>();

        let mut degradations = DegradationReport::default();

        for key in affected {
            let Some(item) = self.items.remove(&key) else {
                continue;
            };
            self.locations[item.analyser].remove(&(item.range, item.kind));

            for surviving in item.regions().difference(region).ranges() {
                degradations.extend(self.insert(item.with_range(surviving)));
            }
        }

        degradations
    }

    pub(crate) fn take_degradations(&mut self) -> DegradationReport {
        mem::take(&mut self.degradations)
    }

    pub(crate) fn clear(&mut self) {
        self.items.clear();
        for locations in &mut self.locations {
            locations.clear();
        }
        self.degradations = DegradationReport::default();
    }
}

#[cfg(test)]
mod test {
    use super::{
        AnalysisWorkQueue, Degradation, DegradationEvent, DegradationReport,
        MAX_WORK_ITEMS_PER_ANALYSER, WORK_SLICE_BYTES,
    };
    use crate::engine::change::{ChangeKinds, Revision};
    use crate::engine::{AnalysisPhase, Priority, WorkCause};
    use crate::ir::{Address, AddressRange, AddressRangeSet, ProblemScope};
    use crate::storage::segments::space::AddressSpaceId;

    fn queue_with(analysers: usize) -> AnalysisWorkQueue {
        AnalysisWorkQueue::with_analysers(analysers)
    }

    #[test]
    fn degradation_reports_are_bounded_by_kind_and_coarsen_scope() {
        let first = AddressSpaceId::from(0u8);
        let second = AddressSpaceId::from(1u8);
        let mut report = DegradationReport::default();

        report.push(DegradationEvent::new(
            Degradation::CausesMerged,
            ProblemScope::Range(AddressRange::new(first, 0x1000u64.into(), 0x1fffu64.into())),
        ));
        report.push(DegradationEvent::new(
            Degradation::CausesMerged,
            ProblemScope::Range(AddressRange::new(first, 0x3000u64.into(), 0x3fffu64.into())),
        ));
        report.push(DegradationEvent::new(
            Degradation::CausesMerged,
            ProblemScope::Range(AddressRange::new(
                second,
                0x1000u64.into(),
                0x1fffu64.into(),
            )),
        ));
        report.push(DegradationEvent::new(
            Degradation::RangesCollapsed,
            ProblemScope::AddressSpace(first),
        ));

        let events = report.into_iter().collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| {
            event.kind() == Degradation::CausesMerged && event.scope() == ProblemScope::Global
        }));
        assert!(events.iter().any(|event| {
            event.kind() == Degradation::RangesCollapsed
                && event.scope() == ProblemScope::AddressSpace(first)
        }));
    }

    #[test]
    fn dispatch_is_ordered_by_address_not_registration() {
        let mut queue = queue_with(2);

        let mut later = AddressRangeSet::new();
        later.insert(Address::in_default_space(0x2000u64));
        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &later,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(0)),
        );

        let mut earlier = AddressRangeSet::new();
        earlier.insert(Address::in_default_space(0x1000u64));
        queue.schedule(
            1,
            1,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &earlier,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(0)),
        );

        let first = queue.pop(WORK_SLICE_BYTES).expect("an item is queued");
        assert_eq!(
            first.range().expect("regional work").start_address(),
            Address::in_default_space(0x1000u64),
            "the earliest address must dispatch first regardless of registration order"
        );
        assert_eq!(first.analyser(), 1);
    }

    #[test]
    fn an_earlier_phase_pre_empts_a_later_one() {
        let mut queue = queue_with(1);

        let mut late = AddressRangeSet::new();
        late.insert(Address::in_default_space(0x1000u64));
        queue.schedule(
            0,
            0,
            AnalysisPhase::Identify,
            Priority::DISCOVERY,
            &late,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(0)),
        );

        let mut early = AddressRangeSet::new();
        early.insert(Address::in_default_space(0x9000u64));
        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &early,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(0)),
        );

        let first = queue.pop(WORK_SLICE_BYTES).expect("an item is queued");
        assert_eq!(first.phase(), AnalysisPhase::Decode);
    }

    #[test]
    fn repeated_work_is_promoted_to_its_most_urgent_priority() {
        let mut queue = queue_with(2);
        let mut regions = AddressRangeSet::new();
        regions.insert(Address::in_default_space(0x1000u64));

        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::ENRICHMENT,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::SYMBOL_CHANGED, Revision::new(1)),
        );
        queue.schedule(
            1,
            1,
            AnalysisPhase::Decode,
            Priority::new(500),
            &regions,
            |range| WorkCause::new(range, ChangeKinds::SYMBOL_CHANGED, Revision::new(1)),
        );
        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(2)),
        );

        let first = queue.pop(WORK_SLICE_BYTES).expect("work is queued");
        assert_eq!(
            first.analyser(),
            0,
            "the repeated item must be re-keyed at its most urgent priority"
        );
        assert_eq!(first.causes().len(), 2);
    }

    #[test]
    fn addressless_work_is_ordered_by_analyser_name() {
        let mut queue = queue_with(2);
        let regions = AddressRangeSet::new();

        queue.schedule(
            0,
            1,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::SPACE_CREATED, Revision::new(1)),
        );
        queue.schedule(
            1,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::SPACE_CREATED, Revision::new(1)),
        );

        let first = queue.pop(WORK_SLICE_BYTES).expect("global work is queued");
        assert_eq!(first.analyser(), 1);
        assert_eq!(first.range(), None);
        assert_eq!(first.causes()[0].range(), None);
    }

    #[test]
    fn causes_survive_partial_cancellation() {
        let mut queue = queue_with(1);
        let space = AddressSpaceId::from(0u8);
        let range = AddressRange::new(space, 0x1000u64.into(), 0x1fffu64.into());
        let cause = WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(7));

        let mut regions = AddressRangeSet::new();
        regions.insert_range(range);
        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &regions,
            |_| cause.clone(),
        );

        let mut cancelled = AddressRangeSet::new();
        cancelled.insert_range(AddressRange::new(space, 0x1800u64.into(), 0x18ffu64.into()));
        queue.cancel(&[AnalysisPhase::Decode], &cancelled);

        let mut surviving = Vec::new();
        while let Some(item) = queue.pop(WORK_SLICE_BYTES) {
            surviving.push(item);
        }

        assert_eq!(surviving.len(), 2, "cancelling the middle splits the item");
        for item in &surviving {
            assert!(
                item.causes().contains(&cause),
                "each surviving part must retain the cause that scheduled it"
            );
            assert!(!cancelled.intersects_range(&item.range().expect("regional work")));
        }
    }

    #[test]
    fn continuation_work_stays_distinct_from_new_region_work() {
        let mut queue = queue_with(1);
        let mut regions = AddressRangeSet::new();
        regions.insert(Address::in_default_space(0x1000u64));

        queue.schedule(
            0,
            0,
            AnalysisPhase::Partition,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(1)),
        );
        let mut yielded = queue.pop_batch(WORK_SLICE_BYTES, 1);
        yielded[0].record_attempt();

        queue.schedule(
            0,
            0,
            AnalysisPhase::Partition,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::SYMBOL_CHANGED, Revision::new(2)),
        );
        queue.requeue_continuation(yielded);

        let fresh = queue
            .pop(WORK_SLICE_BYTES)
            .expect("new region work is queued");
        assert!(!fresh.is_continuation());
        assert_eq!(fresh.attempts(), 0);
        assert_eq!(fresh.causes()[0].kind(), ChangeKinds::SYMBOL_CHANGED);

        let continuation = queue.pop(WORK_SLICE_BYTES).expect("continuation is queued");
        assert!(continuation.is_continuation());
        assert_eq!(
            continuation.attempts(),
            1,
            "yielding must preserve the work item's retry state"
        );
        assert_eq!(continuation.causes()[0].kind(), ChangeKinds::BYTES_WRITTEN);
    }

    #[test]
    fn an_oversized_item_is_split_to_the_cost_budget() {
        let mut queue = queue_with(1);
        let space = AddressSpaceId::from(0u8);
        let range = AddressRange::new(space, 0u64.into(), (WORK_SLICE_BYTES * 2 - 1).into());

        let mut regions = AddressRangeSet::new();
        regions.insert_range(range);
        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(0)),
        );

        let first = queue.pop(WORK_SLICE_BYTES).expect("an item is queued");
        assert_eq!(
            first.range().expect("regional work").size(),
            WORK_SLICE_BYTES
        );
        assert!(!queue.is_empty(), "the remainder stays queued");

        let second = queue
            .pop(WORK_SLICE_BYTES)
            .expect("the remainder is queued");
        assert_eq!(
            second.range().expect("regional work").size(),
            WORK_SLICE_BYTES
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn collapse_preserves_every_address_space() {
        let mut queue = queue_with(1);
        let first = AddressSpaceId::from(0u8);
        let second = AddressSpaceId::from(1u8);
        let mut degradations = Vec::new();

        for index in 0..(MAX_WORK_ITEMS_PER_ANALYSER as u64 + 8) {
            let space = if index % 2 == 0 { first } else { second };
            let base = index * 0x100;
            let kind = if (index / 2) % 2 == 0 {
                ChangeKinds::BYTES_WRITTEN
            } else {
                ChangeKinds::SYMBOL_CHANGED
            };
            let cause = WorkCause::new(None, kind, Revision::new(1));
            let mut regions = AddressRangeSet::new();
            regions.insert_range(AddressRange::new(space, base.into(), (base + 0x0f).into()));
            degradations.extend(queue.schedule(
                0,
                0,
                AnalysisPhase::Decode,
                Priority::DISCOVERY,
                &regions,
                |_| cause.clone(),
            ));
        }

        assert!(degradations.iter().any(|event| {
            event.kind() == Degradation::CausesMerged && event.scope() == ProblemScope::Global
        }));
        assert!(degradations.iter().any(|event| {
            event.kind() == Degradation::RangesCollapsed && event.scope() == ProblemScope::Global
        }));

        let mut drained = AddressRangeSet::new();
        while let Some(item) = queue.pop(u64::MAX) {
            drained.insert_range(item.range().expect("regional work"));
        }

        assert!(
            drained.ranges().any(|range| range.space() == first),
            "collapse must retain the first address space"
        );
        assert!(
            drained.ranges().any(|range| range.space() == second),
            "collapse must retain every other address space, not discard it"
        );
    }

    #[test]
    fn collapse_preserves_the_most_urgent_priority() {
        let mut queue = queue_with(1);
        let space = AddressSpaceId::from(0u8);

        for index in 0..=MAX_WORK_ITEMS_PER_ANALYSER as u64 {
            let mut regions = AddressRangeSet::new();
            regions.insert_range(AddressRange::new(
                space,
                (index * 2).into(),
                (index * 2).into(),
            ));
            queue.schedule(
                0,
                0,
                AnalysisPhase::Decode,
                if index == 0 {
                    Priority::ENRICHMENT
                } else {
                    Priority::DISCOVERY
                },
                &regions,
                |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(1)),
            );
        }

        let item = queue.pop(u64::MAX).expect("collapsed work is queued");
        assert_eq!(
            item.priority,
            Priority::DISCOVERY,
            "collapse must not demote urgent work because a less urgent range sorts first"
        );
    }

    #[test]
    fn same_start_different_extent_items_stay_distinct() {
        let mut queue = queue_with(1);
        let space = AddressSpaceId::from(0u8);
        let start = 0x1000u64;

        for end in [0x10ffu64, 0x1fffu64] {
            let mut regions = AddressRangeSet::new();
            regions.insert_range(AddressRange::new(space, start.into(), end.into()));
            queue.schedule(
                0,
                0,
                AnalysisPhase::Decode,
                Priority::DISCOVERY,
                &regions,
                |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(1)),
            );
        }

        let mut popped = Vec::new();
        while let Some(item) = queue.pop(u64::MAX) {
            popped.push(item.range().expect("regional work"));
        }

        assert_eq!(
            popped.len(),
            2,
            "two ranges sharing a start but differing in extent are distinct work"
        );
        assert!(
            queue.is_empty(),
            "the location index must not strand an item"
        );
    }

    #[test]
    fn work_items_preserve_address_space() {
        let mut queue = queue_with(1);
        let space = AddressSpaceId::from(7u8);
        let address = Address::new(space, 0x1000u64);
        let mut regions = AddressRangeSet::new();
        regions.insert(address);

        queue.schedule(
            0,
            0,
            AnalysisPhase::Decode,
            Priority::DISCOVERY,
            &regions,
            |range| WorkCause::new(range, ChangeKinds::BYTES_WRITTEN, Revision::new(0)),
        );

        let item = queue.pop(WORK_SLICE_BYTES).expect("an item is queued");
        let range = item.range().expect("regional work");
        assert_eq!(range.space(), space);
        assert_eq!(range.start_address(), address);
    }
}
