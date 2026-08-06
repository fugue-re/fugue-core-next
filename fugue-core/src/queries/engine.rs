use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flume::Sender;
use parking_lot::{ArcRwLockWriteGuard, RawRwLock, RwLock};

use crate::engine::Intake;
use crate::il::common::{IlError, IlFormId};
use crate::il::registry::IlRegistry;
use crate::ir::FunctionId;
use crate::project::{ChangeRecord, ChangeSet, Project, ProjectError};
use crate::queries::cache::{CacheLookup, QueryCache, QueryableIl};
use crate::queries::index::ChangeIndex;
use crate::queries::reader::QueryReader;

pub(crate) type QueryPublicationGuard = ArcRwLockWriteGuard<RawRwLock, ()>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IlLookup {
    Current,
    Persisted,
}

pub(crate) struct QueryEngine {
    active: Arc<AtomicBool>,
    publication_lock: Arc<RwLock<()>>,
    project: Arc<RwLock<Project>>,
    cache: Arc<QueryCache>,
    changes: Arc<RwLock<ChangeIndex>>,
    registry: Arc<IlRegistry>,
}

impl QueryEngine {
    pub(crate) fn new(
        project: Arc<RwLock<Project>>,
        registry: Arc<IlRegistry>,
        lifted_cache_bytes: usize,
    ) -> Self {
        let revision = project.read().revision();
        Self {
            active: Arc::new(AtomicBool::new(true)),
            publication_lock: Arc::new(RwLock::new(())),
            project,
            cache: Arc::new(QueryCache::new(lifted_cache_bytes)),
            changes: Arc::new(RwLock::new(ChangeIndex::new(revision))),
            registry,
        }
    }

    pub(crate) fn lookup_lifted<T>(
        cache: &QueryCache,
        registry: &IlRegistry,
        project: &Project,
        function: FunctionId,
        lookup: IlLookup,
    ) -> Result<Option<Arc<T>>, ProjectError>
    where
        T: QueryableIl,
    {
        if lookup == IlLookup::Current {
            match cache.lifted::<T>(function)? {
                CacheLookup::Hit(cached) => return Ok(Some(cached)),
                CacheLookup::Absent => return Ok(None),
                CacheLookup::Miss => {}
            }
        }

        let ir = match project.lifted_erased(registry, function, &T::FORM) {
            Ok(ir) => ir
                .map(|ir| {
                    ir.downcast::<T>()
                        .map(Arc::from)
                        .map_err(|_| IlError::mismatched_artefact(T::FORM))
                })
                .transpose()?,
            Err(ProjectError::Il(IlError::StaleArtefact { .. })) => None,
            Err(error) => return Err(error),
        };
        if lookup == IlLookup::Current {
            cache.insert_lifted(function, ir.clone());
        }
        Ok(ir)
    }

    pub(crate) fn lookup_lifted_erased(
        &self,
        project: &Project,
        function: FunctionId,
        form: &IlFormId,
        lookup: IlLookup,
    ) -> Result<Option<Arc<dyn Any + Send + Sync>>, ProjectError> {
        if lookup == IlLookup::Current {
            match self.cache.lifted_erased(function, form) {
                CacheLookup::Hit(cached) => return Ok(Some(cached)),
                CacheLookup::Absent => return Ok(None),
                CacheLookup::Miss => {}
            }
        }

        let ir = match project.lifted_erased(&self.registry, function, form) {
            Ok(ir) => ir.map(Arc::<dyn Any + Send + Sync>::from),
            Err(ProjectError::Il(IlError::StaleArtefact { .. })) => None,
            Err(error) => return Err(error),
        };
        if lookup == IlLookup::Current {
            let registration = self
                .registry
                .form(form)
                .ok_or_else(|| IlError::unregistered_form(form.clone()))?;
            let size = match ir.as_ref() {
                Some(ir) => (registration.size())(ir.as_ref())?,
                None => 0,
            };
            self.cache
                .insert_lifted_erased(function, form, ir.clone(), size);
        }
        Ok(ir)
    }

    pub(crate) fn insert_lifted_erased(
        &self,
        function: FunctionId,
        form: &IlFormId,
        ir: Arc<dyn Any + Send + Sync>,
    ) -> Result<(), ProjectError> {
        let registration = self
            .registry
            .form(form)
            .ok_or_else(|| IlError::unregistered_form(form.clone()))?;
        let size = (registration.size())(ir.as_ref())?;
        self.cache
            .insert_lifted_erased(function, form, Some(ir), size);
        Ok(())
    }

    pub(crate) fn reader(&self, intake: Sender<Intake>) -> QueryReader {
        QueryReader::new(
            self.active.clone(),
            self.publication_lock.clone(),
            self.project.clone(),
            self.cache.clone(),
            self.changes.clone(),
            self.registry.clone(),
        )
        .with_intake(intake)
    }

    pub(crate) fn begin_publication(&self) -> QueryPublicationGuard {
        self.publication_lock.write_arc()
    }

    pub(crate) fn apply_changes(&self, changes: &ChangeSet) -> bool {
        let collapsed = self.changes.write().apply(changes);

        for record in changes.records() {
            match record {
                ChangeRecord::FunctionAdded { entry, .. }
                | ChangeRecord::FunctionChanged { entry, .. }
                | ChangeRecord::FunctionRemoved { entry, .. } => {
                    self.cache.remove_flow_targets(*entry);
                }
                ChangeRecord::LiftedMaterialised { function, form }
                | ChangeRecord::LiftedRemoved { function, form } => {
                    self.cache.remove_lifted(*function, form);
                }
                ChangeRecord::Resynchronise { .. } => self.cache.clear(),
                _ => {}
            }

            if record.affects_lifted_inputs() {
                self.cache.clear_lifted();
            }
        }

        collapsed
    }

    pub(crate) fn mark_dead(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl Drop for QueryEngine {
    fn drop(&mut self) {
        self.mark_dead();
    }
}

#[cfg(test)]
#[path = "engine/test.rs"]
mod test;
