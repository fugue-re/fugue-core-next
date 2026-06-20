use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;

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

enum Message {
    Flush(SyncSender<Result<(), EntityStorageError>>),
    Shutdown,
    Write(Bytes),
}

pub struct WriteBackWorker {
    tx: SyncSender<Message>,
    pending: Arc<DashMap<Bytes, PendingEntry>>,
    poison: Arc<Mutex<Option<String>>>,
    seq: AtomicU64,
    handle: Mutex<Option<JoinHandle<()>>>,
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
        let (tx, rx) = sync_channel(channel_capacity);
        let pending = Arc::new(DashMap::new());
        let poison = Arc::new(Mutex::new(None));

        let backing = storage.storage_provider();
        let worker_pending = pending.clone();
        let worker_poison = poison.clone();

        let handle = Builder::new()
            .name("entity-writeback".to_owned())
            .spawn(move || {
                run(
                    backing,
                    rx,
                    worker_pending,
                    worker_poison,
                    max_batch,
                    flush_interval,
                );
            })
            .map_err(EntityStorageError::backing)?;

        Ok(Arc::new(Self {
            tx,
            pending,
            poison,
            seq: AtomicU64::new(0),
            handle: Mutex::new(Some(handle)),
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

    pub fn pending(&self, key: &Bytes) -> Option<Option<Bytes>> {
        self.pending.get(key).map(|entry| entry.value.clone())
    }

    pub fn flush(&self) -> Result<(), EntityStorageError> {
        self.poison_check()?;

        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(Message::Flush(reply_tx))
            .map_err(|_| EntityStorageError::backing_with("write-back worker stopped"))?;

        reply_rx
            .recv()
            .map_err(|_| EntityStorageError::backing_with("write-back worker stopped"))?
    }

    pub fn poison_check(&self) -> Result<(), EntityStorageError> {
        match self.poison.lock().as_ref() {
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

        if let Some(handle) = self.handle.lock().take() {
            let _ = handle.join();
        }
    }
}

fn run(
    backing: Arc<dyn ErasedEntityStorageProvider>,
    rx: Receiver<Message>,
    pending: Arc<DashMap<Bytes, PendingEntry>>,
    poison: Arc<Mutex<Option<String>>>,
    max_batch: usize,
    flush_interval: Duration,
) {
    let mut batch = HashSet::new();

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(Message::Write(key)) => {
                batch.insert(key);
                if batch.len() >= max_batch {
                    let keys = batch.drain().collect::<Vec<_>>();
                    let _ = commit(&backing, &pending, &poison, keys);
                }
            }
            Ok(Message::Flush(reply)) => {
                batch.clear();
                let keys = all_keys(&pending);
                let result = commit(&backing, &pending, &poison, keys);
                let _ = reply.send(result);
            }
            Ok(Message::Shutdown) => {
                let keys = all_keys(&pending);
                let _ = commit(&backing, &pending, &poison, keys);
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    let keys = batch.drain().collect::<Vec<_>>();
                    let _ = commit(&backing, &pending, &poison, keys);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                let keys = all_keys(&pending);
                let _ = commit(&backing, &pending, &poison, keys);
                break;
            }
        }
    }
}

fn all_keys(pending: &DashMap<Bytes, PendingEntry>) -> Vec<Bytes> {
    pending.iter().map(|entry| entry.key().clone()).collect()
}

fn commit(
    backing: &Arc<dyn ErasedEntityStorageProvider>,
    pending: &DashMap<Bytes, PendingEntry>,
    poison: &Mutex<Option<String>>,
    keys: Vec<Bytes>,
) -> Result<(), EntityStorageError> {
    let snapshot = keys
        .into_iter()
        .filter_map(|key| {
            pending
                .get(&key)
                .map(|entry| (key.clone(), entry.value.clone(), entry.seq))
        })
        .collect::<Vec<_>>();

    if snapshot.is_empty() {
        return Ok(());
    }

    if let Err(error) = write_batch(backing, &snapshot) {
        *poison.lock() = Some(error.to_string());
        return Err(error);
    }

    for (key, _, seq) in &snapshot {
        pending.remove_if(key, |_, entry| entry.seq == *seq);
    }

    Ok(())
}

fn write_batch(
    backing: &Arc<dyn ErasedEntityStorageProvider>,
    snapshot: &[(Bytes, Option<Bytes>, u64)],
) -> Result<(), EntityStorageError> {
    let mut inserter = backing.bulk_inserter()?;
    for (key, value, _) in snapshot {
        if let Some(bytes) = value {
            inserter.insert(
                BytesOrSlice::from(key.clone()),
                BytesOrSlice::from(bytes.clone()),
            )?;
        }
    }
    inserter.commit()?;

    for (key, value, _) in snapshot {
        if value.is_none() {
            backing.remove(key.as_ref())?;
        }
    }

    Ok(())
}
