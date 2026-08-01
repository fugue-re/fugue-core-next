use std::collections::BTreeMap;

use thiserror::Error;

use crate::il::common::{IlArtefact, IlError, IlLevel};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::FunctionId;
use crate::storage::entities::{EntityWrite, EntityWriteBatch, schema};
use crate::storage::{EntityStorageError, StorageContainer};
use crate::types::common::Revision;

#[derive(Debug, Error)]
pub(crate) enum IlStorageError {
    #[error(transparent)]
    Il(#[from] IlError),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

pub(crate) trait IlPersist: IlArtefact + Sized {
    fn load(
        storage: &StorageContainer,
        function: FunctionId,
    ) -> Result<Option<Self>, IlStorageError> {
        let Some(artefact) = storage.entity::<FunctionId, Self>(&function)? else {
            return Ok(None);
        };

        if artefact.metadata().schema() != Self::SCHEMA {
            return Err(IlError::schema_mismatch(
                Self::LEVEL,
                Self::SCHEMA.value(),
                artefact.metadata().schema().value(),
            )
            .into());
        }

        Ok(Some(artefact))
    }

    fn load_current(
        storage: &StorageContainer,
        function: FunctionId,
        input_revision: Revision,
    ) -> Result<Option<Self>, IlStorageError> {
        let Some(artefact) = Self::load(storage, function)? else {
            return Ok(None);
        };

        if artefact.metadata().input_revision() != input_revision {
            return Err(IlError::stale_artefact(
                Self::LEVEL,
                input_revision.value(),
                artefact.metadata().input_revision().value(),
            )
            .into());
        }

        Ok(Some(artefact))
    }
}

impl<T: IlArtefact> IlPersist for T {}

pub(crate) trait StagedIl: IlPersist {
    fn mutations(stage: &IlStage) -> &BTreeMap<FunctionId, IlMutation<Self>>;
    fn mutations_mut(stage: &mut IlStage) -> &mut BTreeMap<FunctionId, IlMutation<Self>>;
}

impl StagedIl for PCodeIr {
    fn mutations(stage: &IlStage) -> &BTreeMap<FunctionId, IlMutation<Self>> {
        &stage.pcode
    }

    fn mutations_mut(stage: &mut IlStage) -> &mut BTreeMap<FunctionId, IlMutation<Self>> {
        &mut stage.pcode
    }
}

impl StagedIl for ECodeIr {
    fn mutations(stage: &IlStage) -> &BTreeMap<FunctionId, IlMutation<Self>> {
        &stage.ecode
    }

    fn mutations_mut(stage: &mut IlStage) -> &mut BTreeMap<FunctionId, IlMutation<Self>> {
        &mut stage.ecode
    }
}

impl StagedIl for ECodeSsaIr {
    fn mutations(stage: &IlStage) -> &BTreeMap<FunctionId, IlMutation<Self>> {
        &stage.ecode_ssa
    }

    fn mutations_mut(stage: &mut IlStage) -> &mut BTreeMap<FunctionId, IlMutation<Self>> {
        &mut stage.ecode_ssa
    }
}

pub(crate) struct IlMutation<T> {
    base_present: bool,
    value: Option<T>,
}

#[derive(Default)]
pub(crate) struct IlStage {
    pcode: BTreeMap<FunctionId, IlMutation<PCodeIr>>,
    ecode: BTreeMap<FunctionId, IlMutation<ECodeIr>>,
    ecode_ssa: BTreeMap<FunctionId, IlMutation<ECodeSsaIr>>,
}

impl IlStage {
    pub(crate) fn replace<T>(
        &mut self,
        storage: &StorageContainer,
        artefact: T,
    ) -> Result<(), EntityStorageError>
    where
        T: StagedIl,
    {
        let function = artefact.metadata().function();
        if let Some(mutation) = T::mutations_mut(self).get_mut(&function) {
            mutation.value = Some(artefact);
            return Ok(());
        }

        let base_present = storage.contains_entity::<FunctionId, T>(&function)?;
        T::mutations_mut(self).insert(
            function,
            IlMutation {
                base_present,
                value: Some(artefact),
            },
        );
        Ok(())
    }

    pub(crate) fn remove<T>(
        &mut self,
        storage: &StorageContainer,
        function: FunctionId,
    ) -> Result<Option<T>, IlStorageError>
    where
        T: StagedIl,
    {
        if let Some(mutation) = T::mutations_mut(self).get_mut(&function) {
            return Ok(mutation.value.take());
        }

        let previous = T::load(storage, function)?;
        T::mutations_mut(self).insert(
            function,
            IlMutation {
                base_present: previous.is_some(),
                value: None,
            },
        );
        Ok(previous)
    }

    pub(crate) fn prepare(&self) -> Result<EntityWriteBatch, EntityStorageError> {
        let capacity = self
            .pcode
            .len()
            .saturating_add(self.ecode.len())
            .saturating_add(self.ecode_ssa.len());
        let mut writes = Vec::with_capacity(capacity);
        self.prepare_level::<PCodeIr>(&mut writes)?;
        self.prepare_level::<ECodeIr>(&mut writes)?;
        self.prepare_level::<ECodeSsaIr>(&mut writes)?;
        Ok(writes)
    }

    fn prepare_level<T>(&self, writes: &mut EntityWriteBatch) -> Result<(), EntityStorageError>
    where
        T: StagedIl,
    {
        for (&function, mutation) in T::mutations(self) {
            if !mutation.base_present && mutation.value.is_none() {
                continue;
            }
            let value = mutation
                .value
                .as_ref()
                .map(|artefact| {
                    rkyv::to_bytes::<rkyv::rancor::Error>(artefact)
                        .map_err(EntityStorageError::encode)
                })
                .transpose()?;
            let key = schema::make_key::<FunctionId, T>(&function);
            writes.push(match value {
                Some(value) => EntityWrite::insert_archive(key, value),
                None => EntityWrite::remove(key),
            });
        }
        Ok(())
    }

    pub(crate) fn for_each_change(&self, mut f: impl FnMut(FunctionId, IlLevel, bool)) {
        self.for_each_level::<PCodeIr>(&mut f);
        self.for_each_level::<ECodeIr>(&mut f);
        self.for_each_level::<ECodeSsaIr>(&mut f);
    }

    fn for_each_level<T>(&self, f: &mut impl FnMut(FunctionId, IlLevel, bool))
    where
        T: StagedIl,
    {
        for (&function, mutation) in T::mutations(self) {
            if mutation.base_present || mutation.value.is_some() {
                f(function, T::LEVEL, mutation.value.is_some());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::IlStage;
    use crate::il::common::{IlGraph, IlMetadata};
    use crate::il::pcode::{PCODE_SCHEMA_VERSION, PCodeIr};
    use crate::ir::FunctionId;
    use crate::storage::{EntityStorage, InMemoryEntityStorage, SegmentStorage, StorageContainer};
    use crate::types::Revision;

    fn pcode(function: FunctionId, revision: Revision) -> PCodeIr {
        PCodeIr::new(
            IlMetadata::new(function, PCODE_SCHEMA_VERSION, revision),
            IlGraph::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn storage() -> StorageContainer {
        StorageContainer::from_parts(
            EntityStorage::new(InMemoryEntityStorage::new()),
            SegmentStorage::empty(),
        )
        .expect("transient storage should initialise")
    }

    #[test]
    fn repeated_replacement_retains_only_the_final_artefact() {
        let storage = storage();
        let function = FunctionId::new(7);
        let expected = pcode(function, Revision::from(2));
        let encoded =
            rkyv::to_bytes::<rkyv::rancor::Error>(&expected).expect("artefact should encode");
        let mut stage = IlStage::default();

        stage
            .replace(&storage, pcode(function, Revision::from(1)))
            .expect("first replacement should stage");
        stage
            .replace(&storage, expected)
            .expect("second replacement should coalesce");

        let writes = stage.prepare().expect("stage should prepare");
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].1.as_deref(), Some(encoded.as_slice()));

        let mut changes = Vec::new();
        stage.for_each_change(|function, level, present| {
            changes.push((function, level, present));
        });
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, function);
        assert!(changes[0].2);
    }

    #[test]
    fn removing_an_unpublished_replacement_elides_the_mutation() {
        let storage = storage();
        let function = FunctionId::new(7);
        let mut stage = IlStage::default();

        stage
            .replace(&storage, pcode(function, Revision::from(1)))
            .expect("replacement should stage");
        assert!(
            stage
                .remove::<PCodeIr>(&storage, function)
                .expect("replacement should be removable")
                .is_some()
        );

        assert!(stage.prepare().expect("stage should prepare").is_empty());
        stage.for_each_change(|_, _, _| panic!("elided mutation must not publish a change"));
    }

    #[test]
    fn removing_a_missing_artefact_caches_its_absence() {
        let storage = storage();
        let function = FunctionId::new(7);
        let mut stage = IlStage::default();

        assert!(
            stage
                .remove::<PCodeIr>(&storage, function)
                .expect("missing artefact lookup should succeed")
                .is_none()
        );
        assert!(
            stage
                .pcode
                .get(&function)
                .is_some_and(|mutation| !mutation.base_present && mutation.value.is_none())
        );
        assert!(
            stage
                .remove::<PCodeIr>(&storage, function)
                .expect("cached missing artefact lookup should succeed")
                .is_none()
        );
    }
}
