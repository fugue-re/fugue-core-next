use std::sync::Arc;
use std::time::Duration;

use flume::{Receiver, Sender, TryRecvError, TrySendError};
use smol_str::SmolStr;

use crate::engine::change::ChangeFilter;
use crate::engine::{AnalysisEngine, DEFAULT_SUBSCRIPTION_CAPACITY, EngineError};
use crate::ir::AddressRangeSet;
use crate::project::{
    ChangeCategory, ChangeKinds, ChangeRecord, ChangeSet, ChangeSource, MAX_DETAILED_CHANGE_RECORDS,
};

pub(crate) struct Subscriber {
    rx: Receiver<Arc<ChangeSet>>,
    tx: Sender<Arc<ChangeSet>>,
    filter: ChangeFilter,
}

impl Subscriber {
    pub(crate) fn new(
        tx: Sender<Arc<ChangeSet>>,
        rx: Receiver<Arc<ChangeSet>>,
        filter: ChangeFilter,
    ) -> Self {
        Self { rx, tx, filter }
    }

    pub(crate) fn materialise(
        &self,
        changes: &ChangeSet,
        resync: &mut Option<Arc<ChangeSet>>,
    ) -> bool {
        if self.tx.receiver_count() == 1 {
            return false;
        }
        if changes.len() > MAX_DETAILED_CHANGE_RECORDS {
            return self.resync(Self::resynchronisation(changes, resync));
        }

        let scoped = match self.filter.apply(changes) {
            Some(scoped) => Arc::new(scoped),
            None => return true,
        };

        match self.tx.try_send(scoped) {
            Ok(()) => true,
            Err(TrySendError::Disconnected(_)) => false,
            Err(TrySendError::Full(_)) => self.resync(Self::resynchronisation(changes, resync)),
        }
    }

    fn resynchronisation(
        changes: &ChangeSet,
        resync: &mut Option<Arc<ChangeSet>>,
    ) -> Arc<ChangeSet> {
        resync
            .get_or_insert_with(|| {
                Arc::new(
                    ChangeSet::with_records(
                        changes.revision(),
                        [ChangeRecord::Resynchronise {
                            to: changes.revision(),
                        }],
                    )
                    .with_provenance(ChangeSource::engine("resynchronisation")),
                )
            })
            .clone()
    }

    pub(crate) fn resync(&self, changes: Arc<ChangeSet>) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(_) => {}
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return false,
            }
        }

        self.tx.try_send(changes).is_ok()
    }
}

pub struct SubscriptionBuilder<'a> {
    engine: &'a AnalysisEngine,
    filter: ChangeFilter,
    capacity: usize,
}

impl<'a> SubscriptionBuilder<'a> {
    pub(crate) fn new(engine: &'a AnalysisEngine) -> Self {
        Self {
            engine,
            filter: ChangeFilter::new(),
            capacity: DEFAULT_SUBSCRIPTION_CAPACITY,
        }
    }

    pub fn with_kinds(mut self, kinds: ChangeKinds) -> Self {
        self.filter = self.filter.with_kinds(kinds);
        self
    }

    pub fn with_region(mut self, region: AddressRangeSet) -> Self {
        self.filter = self.filter.with_region(region);
        self
    }

    pub fn with_category(mut self, category: ChangeCategory) -> Self {
        self.filter = self.filter.with_category(category);
        self
    }

    pub fn with_source_label(mut self, label: impl Into<SmolStr>) -> Self {
        self.filter = self.filter.with_source_label(label);
        self
    }

    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.set_capacity(capacity);
        self
    }

    pub fn build(self) -> Result<Subscription, EngineError> {
        self.engine.open_subscription(self.filter, self.capacity)
    }
}

pub struct Subscription {
    rx: Receiver<Arc<ChangeSet>>,
}

impl Subscription {
    pub(crate) fn new(rx: Receiver<Arc<ChangeSet>>) -> Self {
        Self { rx }
    }

    pub fn recv(&self) -> Result<Arc<ChangeSet>, EngineError> {
        self.rx.recv().map_err(|_| EngineError::Stopped)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Arc<ChangeSet>, EngineError> {
        self.rx.recv_timeout(timeout).map_err(|error| match error {
            flume::RecvTimeoutError::Disconnected => EngineError::Stopped,
            flume::RecvTimeoutError::Timeout => EngineError::SubscriptionTimeout,
        })
    }

    pub fn try_recv(&self) -> Result<Arc<ChangeSet>, EngineError> {
        self.rx.try_recv().map_err(|error| match error {
            TryRecvError::Disconnected => EngineError::Stopped,
            TryRecvError::Empty => EngineError::SubscriptionEmpty,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<ChangeSet>> + '_ {
        self.rx.iter()
    }

    pub fn try_iter(&self) -> impl Iterator<Item = Arc<ChangeSet>> + '_ {
        self.rx.try_iter()
    }

    pub fn drain_merged(&self) -> Option<ChangeSet> {
        let mut merged = None::<ChangeSet>;
        for changes in self.rx.try_iter() {
            match merged.as_mut() {
                Some(batch) => batch.merge(&changes),
                None => merged = Some((*changes).clone()),
            }
        }
        merged
    }

    pub fn recv_batch(&self) -> Result<ChangeSet, EngineError> {
        let mut batch = (*self.recv()?).clone();
        if let Some(rest) = self.drain_merged() {
            batch.merge(&rest);
        }
        Ok(batch)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::Subscriber;
    use crate::engine::change::ChangeFilter;
    use crate::ir::{Address, AddressRange};
    use crate::project::{ChangeRecord, ChangeSet, MAX_DETAILED_CHANGE_RECORDS};
    use crate::storage::segments::space::AddressSpaceId;
    use crate::types::Revision;

    #[test]
    fn lagged_subscriber_receives_resync_change() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = flume::bounded(1);
        let subscriber = Subscriber::new(tx, rx.clone(), ChangeFilter::new());
        let first = Arc::new(ChangeSet::with_records(
            Revision::new(1),
            [ChangeRecord::SpaceCreated {
                space: AddressSpaceId::from(0u8),
            }],
        ));
        let second = Arc::new(ChangeSet::with_records(
            Revision::new(2),
            [ChangeRecord::SpaceCreated {
                space: AddressSpaceId::from(0u8),
            }],
        ));
        let mut resync = None;

        assert!(subscriber.materialise(&first, &mut resync));
        assert!(subscriber.materialise(&second, &mut resync));

        let delivered = rx.try_recv()?;
        assert_eq!(&*delivered, &*resync.expect("resync must be materialised"));
        assert!(rx.try_recv().is_err());

        Ok(())
    }

    #[test]
    fn oversized_publication_delivers_one_resynchronisation_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = flume::bounded(1);
        let subscriber = Subscriber::new(tx, rx.clone(), ChangeFilter::new());
        let records = (0..=MAX_DETAILED_CHANGE_RECORDS)
            .map(|index| ChangeRecord::BytesWritten {
                range: AddressRange::point(Address::from(index as u64)),
            })
            .collect::<Vec<_>>();
        let changes = ChangeSet::with_records(Revision::new(1), records);
        let mut resynchronisation = None;

        assert!(subscriber.materialise(&changes, &mut resynchronisation));

        let delivered = rx.try_recv()?;
        assert_eq!(
            delivered.records(),
            &[ChangeRecord::Resynchronise {
                to: Revision::new(1)
            }]
        );
        assert_eq!(delivered.provenance().sources().count(), 1);

        Ok(())
    }

    #[test]
    fn dropped_subscription_is_pruned_despite_internal_receiver() {
        let (tx, rx) = flume::bounded(1);
        let subscriber = Subscriber::new(tx, rx.clone(), ChangeFilter::new());
        drop(rx);
        let changes = Arc::new(ChangeSet::new(Revision::new(1)));
        assert!(!subscriber.materialise(&changes, &mut None));
    }
}
