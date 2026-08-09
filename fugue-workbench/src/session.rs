use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fugue_core::engine::{AnalysisEngine, EngineError};
use fugue_core::ir::{
    Address, IncompleteFunction, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
    symbol,
};
use fugue_core::loader::{LoadableFromBytes, Loader};
use fugue_core::project::{ChangeSet, Project};
use fugue_core::queries::QueryReader;
use tokio::sync::broadcast;

use crate::bindings::{ChangeEvent, MetricsResponse};
use crate::error::WorkbenchError;

const WORKBENCH_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(2);
const FEED_POLL: Duration = Duration::from_millis(200);

pub struct Session {
    engine: Arc<AnalysisEngine>,
    reader: QueryReader,
    symbol_indices: Mutex<HashMap<Address, usize>>,
    shutdown: Arc<AtomicBool>,
}

impl Session {
    pub fn open(
        input: &Path,
        persist: bool,
        changes: broadcast::Sender<ChangeEvent>,
    ) -> Result<Self, WorkbenchError> {
        let project = if persist {
            Project::from_file(input)?
        } else {
            let loader = Loader::from_file(input)?;
            Project::new_transient(&loader)?
        };
        Self::from_project(project, changes)
    }

    pub fn from_bytes(
        bytes: Vec<u8>,
        changes: broadcast::Sender<ChangeEvent>,
    ) -> Result<Self, WorkbenchError> {
        let loader = Loader::from_bytes(bytes)?;
        Self::from_project(Project::new_transient(&loader)?, changes)
    }

    fn from_project(
        project: Project,
        changes: broadcast::Sender<ChangeEvent>,
    ) -> Result<Self, WorkbenchError> {
        let engine = Arc::new(AnalysisEngine::new(project)?);
        let reader = engine.query_reader()?;
        let subscription = engine.subscribe().build()?;
        let shutdown = Arc::new(AtomicBool::new(false));

        let stop = Arc::clone(&shutdown);
        thread::Builder::new()
            .name("workbench-changes".to_owned())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match subscription.recv_timeout(FEED_POLL) {
                        Ok(first) => {
                            let mut batch = (*first).clone();
                            if let Some(rest) = subscription.drain_merged() {
                                batch.merge(&rest);
                            }
                            let _ = changes.send(ChangeEvent::from_change_set(&batch));
                        }
                        Err(EngineError::SubscriptionTimeout) => continue,
                        Err(_) => break,
                    }
                }
            })
            .expect("spawn change-feed thread");

        let analysis = Arc::clone(&engine);
        let stop = Arc::clone(&shutdown);
        thread::Builder::new()
            .name("workbench-analysis".to_owned())
            .spawn(move || {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                if let Err(error) = analysis.analyse() {
                    tracing::error!(%error, "analysis run failed");
                }
            })
            .expect("spawn analysis thread");

        Ok(Self {
            engine,
            reader,
            symbol_indices: Mutex::new(HashMap::new()),
            shutdown,
        })
    }

    pub async fn define_function(&self, address: Address) -> Result<u64, WorkbenchError> {
        self.apply(move |engine| engine.add_function(IncompleteFunction::new(address)))
            .await
    }

    pub async fn undefine_function(&self, address: Address) -> Result<u64, WorkbenchError> {
        self.apply(move |engine| engine.remove_function(address)).await
    }

    pub async fn patch_bytes(&self, address: Address, bytes: Vec<u8>) -> Result<u64, WorkbenchError> {
        self.apply(move |engine| engine.write_bytes(address, bytes)).await
    }

    pub async fn rename(
        &self,
        address: Address,
        name: String,
        function: bool,
    ) -> Result<u64, WorkbenchError> {
        let index = {
            let mut indices = self.symbol_indices.lock().expect("symbol index map poisoned");
            let next = indices.len();
            *indices.entry(address).or_insert(next)
        };
        let properties = if function {
            SymbolProperties::FUNCTION
        } else {
            SymbolProperties::NONE
        };
        let entry = SymbolEntry::new(address, symbol(&name), properties);
        let symbol_index = SymbolIndex::new(WORKBENCH_SELECTOR, index);
        self.apply(move |engine| engine.add_symbol(symbol_index, entry)).await
    }

    pub async fn read<T, F>(&self, task: F) -> Result<T, WorkbenchError>
    where
        F: FnOnce(&QueryReader) -> Result<T, WorkbenchError> + Send + 'static,
        T: Send + 'static,
    {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || task(&reader))
            .await
            .map_err(|_| WorkbenchError::TaskCancelled)?
    }

    pub async fn metrics(&self) -> Result<MetricsResponse, WorkbenchError> {
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || MetricsResponse::from_snapshot(&engine.metrics()))
            .await
            .map_err(|_| WorkbenchError::TaskCancelled)
    }

    async fn apply<F>(&self, task: F) -> Result<u64, WorkbenchError>
    where
        F: FnOnce(&AnalysisEngine) -> Result<ChangeSet, EngineError> + Send + 'static,
    {
        let engine = Arc::clone(&self.engine);
        let changes = tokio::task::spawn_blocking(move || task(&engine))
            .await
            .map_err(|_| WorkbenchError::TaskCancelled)??;
        Ok(changes.revision().value())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.engine.cancel();
    }
}
