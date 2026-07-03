use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use flume::{Receiver, RecvTimeoutError, Sender};
use rustc_hash::FxHashSet;

use crate::storage::entities::{
    EntityStorage, EntityStorageError, EntityStorageProvider, ErasedEntityStorageProvider,
};
use crate::types::BytesOrSlice;

const DEFAULT_CHANNEL_CAPACITY: usize = 4096;
const DEFAULT_MAX_BATCH: usize = 1024;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(5);

struct PendingEntry {
    value: Option<Bytes>,
    seq: u64,
}

struct PendingWrite {
    key: Bytes,
    value: Option<Bytes>,
    seq: u64,
}

enum Message {
    Flush(Sender<Result<(), EntityStorageError>>),
    Shutdown,
    Write(Bytes),
}

pub enum WriteBackAction {
    Insert(Bytes),
    Remove,
}

pub struct WriteBackWorker {
    tx: Sender<Message>,
    pending: Arc<DashMap<Bytes, PendingEntry>>,
    poison: Arc<OnceLock<String>>,
    seq: AtomicU64,
    handle: Option<JoinHandle<()>>,
}

impl WriteBackWorker {
    pub fn new(storage: EntityStorage) -> Result<Arc<Self>, EntityStorageError> {
        Self::with_options(
            storage,
            DEFAULT_CHANNEL_CAPACITY,
            DEFAULT_MAX_BATCH,
            DEFAULT_FLUSH_INTERVAL,
        )
    }

    pub fn with_options(
        storage: EntityStorage,
        channel_capacity: usize,
        max_batch: usize,
        flush_interval: Duration,
    ) -> Result<Arc<Self>, EntityStorageError> {
        let (tx, rx) = flume::bounded(channel_capacity);
        let pending = Arc::new(DashMap::new());
        let poison = Arc::new(OnceLock::new());

        let worker = Worker {
            backing: storage.storage_provider(),
            pending: pending.clone(),
            poison: poison.clone(),
            max_batch,
            flush_interval,
        };

        let handle = Builder::new()
            .name("entity-write-back".to_owned())
            .spawn(move || worker.run(rx))
            .map_err(EntityStorageError::backing)?;

        Ok(Arc::new(Self {
            tx,
            pending,
            poison,
            seq: AtomicU64::new(0),
            handle: Some(handle),
        }))
    }

    pub fn enqueue(&self, key: Bytes, value: Option<Bytes>) -> Result<(), EntityStorageError> {
        self.poison_check()?;

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        self.pending
            .insert(key.clone(), PendingEntry { value, seq });

        self.tx
            .send(Message::Write(key))
            .map_err(|_| EntityStorageError::backing_with("write-back worker stopped"))
    }

    pub fn pending(&self, key: &Bytes) -> Option<WriteBackAction> {
        self.pending.get(key).map(|entry| match &entry.value {
            Some(bytes) => WriteBackAction::Insert(bytes.clone()),
            None => WriteBackAction::Remove,
        })
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = flume::bounded(1);
        self.tx
            .send(Message::Flush(reply_tx))
            .map_err(|_| EntityStorageError::backing_with("write-back worker stopped"))?;

        reply_rx
            .recv()
            .map_err(|_| EntityStorageError::backing_with("write-back worker stopped"))?
    }

    pub fn poison_check(&self) -> Result<(), EntityStorageError> {
        match self.poison.get() {
            Some(message) => Err(EntityStorageError::backing_with(format!(
                "write-back worker poisoned: {message}"
            ))),
            None => Ok(()),
        }
    }
}

impl Drop for WriteBackWorker {
    fn drop(&mut self) {
        let _ = self.tx.send(Message::Shutdown);

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct Worker {
    backing: Arc<dyn ErasedEntityStorageProvider>,
    pending: Arc<DashMap<Bytes, PendingEntry>>,
    poison: Arc<OnceLock<String>>,
    max_batch: usize,
    flush_interval: Duration,
}

impl Worker {
    fn run(self, rx: Receiver<Message>) {
        let mut batch = FxHashSet::default();
        let mut snapshot = Vec::new();

        loop {
            match rx.recv_timeout(self.flush_interval) {
                Ok(Message::Write(key)) => {
                    batch.insert(key);
                    if batch.len() >= self.max_batch {
                        let _ = self.commit_batch(&mut batch, &mut snapshot);
                    }
                }
                Ok(Message::Flush(reply)) => {
                    batch.clear();
                    let _ = reply.send(self.commit_all(&mut snapshot));
                }
                Ok(Message::Shutdown) => {
                    let _ = self.commit_all(&mut snapshot);
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !batch.is_empty() {
                        let _ = self.commit_batch(&mut batch, &mut snapshot);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = self.commit_all(&mut snapshot);
                    break;
                }
            }
        }
    }

    fn commit_batch(
        &self,
        batch: &mut FxHashSet<Bytes>,
        snapshot: &mut Vec<PendingWrite>,
    ) -> Result<(), EntityStorageError> {
        snapshot.clear();
        snapshot.extend(batch.drain().filter_map(|key| self.snapshot_of(key)));

        self.commit(snapshot)
    }

    fn commit_all(&self, snapshot: &mut Vec<PendingWrite>) -> Result<(), EntityStorageError> {
        snapshot.clear();
        snapshot.extend(self.pending.iter().map(|entry| PendingWrite {
            key: entry.key().clone(),
            value: entry.value.clone(),
            seq: entry.seq,
        }));

        self.commit(snapshot)
    }

    fn snapshot_of(&self, key: Bytes) -> Option<PendingWrite> {
        let entry = self.pending.get(&key)?;
        Some(PendingWrite {
            value: entry.value.clone(),
            seq: entry.seq,
            key,
        })
    }

    fn commit(&self, snapshot: &[PendingWrite]) -> Result<(), EntityStorageError> {
        if snapshot.is_empty() {
            return Ok(());
        }

        if let Err(error) = self.write_batch(snapshot) {
            tracing::error!(
                "write-back commit of {} entries failed, poisoning worker: {error}",
                snapshot.len()
            );
            let _ = self.poison.set(error.to_string());
            return Err(error);
        }

        for write in snapshot {
            self.pending
                .remove_if(&write.key, |_, entry| entry.seq == write.seq);
        }

        Ok(())
    }

    fn write_batch(&self, snapshot: &[PendingWrite]) -> Result<(), EntityStorageError> {
        let writer = match self.backing.transactional_writer() {
            Ok(writer) => writer,
            Err(EntityStorageError::Unsupported(_)) => return self.write_batch_buffered(snapshot),
            Err(error) => return Err(error),
        };

        for write in snapshot {
            match &write.value {
                Some(bytes) => {
                    writer.insert(write.key.as_ref(), BytesOrSlice::from(bytes.as_ref()))?
                }
                None => writer.remove(write.key.as_ref())?,
            }
        }

        writer.commit()
    }

    fn write_batch_buffered(&self, snapshot: &[PendingWrite]) -> Result<(), EntityStorageError> {
        let mut inserter = self.backing.bulk_inserter()?;
        for write in snapshot {
            if let Some(bytes) = &write.value {
                inserter.insert(
                    BytesOrSlice::from(write.key.as_ref()),
                    BytesOrSlice::from(bytes.as_ref()),
                )?;
            }
        }
        inserter.commit()?;

        for write in snapshot {
            if write.value.is_none() {
                self.backing.remove(write.key.as_ref())?;
            }
        }

        Ok(())
    }
}
