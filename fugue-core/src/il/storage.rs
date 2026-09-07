use std::any::Any;
use std::collections::BTreeMap;

use thiserror::Error;

use crate::il::common::{IlError, IlFormId, PersistableIl};
use crate::ir::FunctionId;
use crate::storage::entities::schema::{
    ENTITY_IL_OVERRIDE_ID, ENTITY_KEY_IL_OVERRIDE_ID, Entity, EntityId, EntityKey, EntityKeyCodec,
    EntityKeyId,
};
use crate::storage::entities::{EntityWrite, EntityWriteBatch};
use crate::storage::{EntityStorageError, StorageContainer};
use crate::types::Revision;

#[derive(Debug, Error)]
pub(crate) enum IlStorageError {
    #[error(transparent)]
    Il(#[from] IlError),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct IlOverrideKey {
    function: FunctionId,
    form: IlFormId,
}

impl IlOverrideKey {
    pub(crate) fn new(function: FunctionId, form: IlFormId) -> Self {
        Self { function, form }
    }

    pub(crate) fn function(&self) -> FunctionId {
        self.function
    }

    pub(crate) fn form(&self) -> &IlFormId {
        &self.form
    }
}

impl EntityKeyCodec for IlOverrideKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        Some(Self {
            function: FunctionId::decode(input)?,
            form: IlFormId::decode(input)?,
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.function.encode(output);
        self.form.encode(output);
    }
}

impl EntityKey for IlOverrideKey {
    const ID: EntityKeyId = ENTITY_KEY_IL_OVERRIDE_ID;
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct IlOverride {
    form: String,
    schema: u16,
    input_revision: u64,
    bytes: Vec<u8>,
}

impl Entity for IlOverride {
    const ID: EntityId = ENTITY_IL_OVERRIDE_ID;
}

type IlEncodeFn = fn(&(dyn Any + Send + Sync)) -> Result<IlOverride, EntityStorageError>;

fn encode_erased<T: PersistableIl>(
    artefact: &(dyn Any + Send + Sync),
) -> Result<IlOverride, EntityStorageError> {
    let artefact = artefact
        .downcast_ref::<T>()
        .ok_or_else(|| EntityStorageError::encode(IlError::mismatched_source(T::FORM)))?;

    IlOverride::encode(artefact)
}

impl IlOverride {
    fn encode<T: PersistableIl>(artefact: &T) -> Result<Self, EntityStorageError> {
        Ok(Self {
            form: String::from(T::FORM_IDENTIFIER),
            schema: T::SCHEMA.value(),
            input_revision: artefact.metadata().input_revision().value(),
            bytes: rkyv::to_bytes::<rkyv::rancor::Error>(artefact)
                .map_err(EntityStorageError::encode)?
                .into_vec(),
        })
    }

    pub(crate) fn input_revision(&self) -> u64 {
        self.input_revision
    }

    fn decode<T: PersistableIl>(&self) -> Result<T, IlStorageError> {
        if self.form != T::FORM_IDENTIFIER {
            return Err(IlError::dialect_unavailable(self.form.clone()).into());
        }
        if self.schema != T::SCHEMA.value() {
            return Err(IlError::schema_mismatch(T::FORM, T::SCHEMA.value(), self.schema).into());
        }

        rkyv::from_bytes::<T, rkyv::rancor::Error>(&self.bytes)
            .map_err(|error| EntityStorageError::decode(error).into())
    }
}

pub(crate) trait IlPersist: PersistableIl {
    fn load(
        storage: &StorageContainer,
        function: FunctionId,
    ) -> Result<Option<Self>, IlStorageError> {
        let key = IlOverrideKey::new(function, Self::FORM);
        let Some(stored) = storage.entity::<IlOverrideKey, IlOverride>(&key)? else {
            return Ok(None);
        };

        stored.decode::<Self>().map(Some)
    }

    fn load_current(
        storage: &StorageContainer,
        function: FunctionId,
        input_revision: Revision,
    ) -> Result<Option<Self>, IlStorageError> {
        let key = IlOverrideKey::new(function, Self::FORM);
        let Some(stored) = storage.entity::<IlOverrideKey, IlOverride>(&key)? else {
            return Ok(None);
        };

        if stored.input_revision() != input_revision.value() {
            return Err(IlError::stale_artefact(
                Self::FORM,
                input_revision.value(),
                stored.input_revision(),
            )
            .into());
        }

        stored.decode::<Self>().map(Some)
    }
}

impl<T: PersistableIl> IlPersist for T {}

struct StagedIlArtefact {
    artefact: Box<dyn Any + Send + Sync>,
    encode: IlEncodeFn,
}

struct StagedIlRecord {
    base_present: bool,
    value: Option<StagedIlArtefact>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IlStagedChange {
    Materialised {
        function: FunctionId,
        form: IlFormId,
    },
    Removed {
        function: FunctionId,
        form: IlFormId,
    },
}

#[derive(Default)]
pub(crate) struct IlStaging {
    records: BTreeMap<IlOverrideKey, StagedIlRecord>,
    stored: Option<BTreeMap<FunctionId, Vec<IlFormId>>>,
}

impl IlStaging {
    pub(crate) fn replace<T>(
        &mut self,
        storage: &StorageContainer,
        artefact: T,
    ) -> Result<(), EntityStorageError>
    where
        T: PersistableIl,
    {
        let key = IlOverrideKey::new(artefact.metadata().function(), T::FORM);
        let staged = StagedIlArtefact {
            artefact: Box::new(artefact),
            encode: encode_erased::<T>,
        };
        if let Some(record) = self.records.get_mut(&key) {
            record.value = Some(staged);
            return Ok(());
        }

        let base_present = storage.contains_entity::<IlOverrideKey, IlOverride>(&key)?;
        self.records.insert(
            key,
            StagedIlRecord {
                base_present,
                value: Some(staged),
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
        T: PersistableIl,
    {
        let key = IlOverrideKey::new(function, T::FORM);
        if let Some(record) = self.records.get_mut(&key) {
            return Ok(record.value.take().and_then(|staged| {
                staged
                    .artefact
                    .downcast::<T>()
                    .ok()
                    .map(|artefact| *artefact)
            }));
        }

        let previous = T::load(storage, function)?;
        self.records.insert(
            key,
            StagedIlRecord {
                base_present: previous.is_some(),
                value: None,
            },
        );
        Ok(previous)
    }

    pub(crate) fn remove_form(
        &mut self,
        storage: &StorageContainer,
        function: FunctionId,
        form: &IlFormId,
    ) -> Result<bool, EntityStorageError> {
        let key = IlOverrideKey::new(function, form.clone());
        if let Some(record) = self.records.get_mut(&key) {
            return Ok(record.value.take().is_some());
        }

        let base_present = storage.contains_entity::<IlOverrideKey, IlOverride>(&key)?;
        self.records.insert(
            key,
            StagedIlRecord {
                base_present,
                value: None,
            },
        );
        Ok(base_present)
    }

    pub(crate) fn prepare(&self) -> Result<EntityWriteBatch, EntityStorageError> {
        let mut writes = EntityWriteBatch::with_capacity(self.records.len());
        for (key, record) in &self.records {
            if !record.base_present && record.value.is_none() {
                continue;
            }
            let key = IlOverride::ID.key_for(key);
            writes.push(match &record.value {
                Some(staged) => EntityWrite::insert_archived(
                    key,
                    rkyv::to_bytes::<rkyv::rancor::Error>(&(staged.encode)(
                        staged.artefact.as_ref(),
                    )?)
                    .map_err(EntityStorageError::encode)?,
                ),
                None => EntityWrite::remove(key),
            });
        }
        Ok(writes)
    }

    pub(crate) fn remove_function(
        &mut self,
        storage: &StorageContainer,
        function: FunctionId,
    ) -> Result<usize, EntityStorageError> {
        if self.stored.is_none() {
            let mut stored = BTreeMap::<FunctionId, Vec<IlFormId>>::new();
            for key in storage.entities().keys::<IlOverrideKey, IlOverride>()? {
                let key = key?;
                stored.entry(key.function()).or_default().push(key.form);
            }
            self.stored = Some(stored);
        }

        let forms = self
            .stored
            .as_ref()
            .and_then(|stored| stored.get(&function))
            .map_or(&[][..], Vec::as_slice);

        let mut removed = 0usize;
        for form in forms {
            if self
                .records
                .insert(
                    IlOverrideKey::new(function, form.clone()),
                    StagedIlRecord {
                        base_present: true,
                        value: None,
                    },
                )
                .is_none()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub(crate) fn for_each_change(&self, mut f: impl FnMut(IlStagedChange)) {
        for (key, record) in &self.records {
            if !record.base_present && record.value.is_none() {
                continue;
            }
            let change = if record.value.is_some() {
                IlStagedChange::Materialised {
                    function: key.function(),
                    form: key.form().clone(),
                }
            } else {
                IlStagedChange::Removed {
                    function: key.function(),
                    form: key.form().clone(),
                }
            };
            f(change);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::il::common::{IlArtefact, IlGraph, IlMetadata};
    use crate::il::pcode::PCodeIr;
    use crate::storage::{EntityStorage, InMemoryEntityStorage, SegmentStorage};

    fn pcode(function: FunctionId, revision: Revision) -> PCodeIr {
        PCodeIr::new(
            IlMetadata::new(function, revision),
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
        let mut staging = IlStaging::default();

        staging
            .replace(&storage, pcode(function, Revision::from(1)))
            .expect("first replacement should stage");
        staging
            .replace(&storage, pcode(function, Revision::from(2)))
            .expect("second replacement should coalesce");

        let writes = staging.prepare().expect("staging should prepare");
        assert_eq!(writes.len(), 1);

        let mut changes = Vec::new();
        staging.for_each_change(|change| changes.push(change));
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            IlStagedChange::Materialised {
                function,
                form: PCodeIr::FORM,
            }
        );
    }

    #[test]
    fn removing_an_unpublished_replacement_elides_the_mutation() {
        let storage = storage();
        let function = FunctionId::new(7);
        let mut staging = IlStaging::default();

        staging
            .replace(&storage, pcode(function, Revision::from(1)))
            .expect("replacement should stage");
        assert!(
            staging
                .remove::<PCodeIr>(&storage, function)
                .expect("replacement should be removable")
                .is_some()
        );

        assert!(
            staging
                .prepare()
                .expect("staging should prepare")
                .is_empty()
        );
        staging.for_each_change(|_| panic!("elided record must not publish a change"));
    }

    #[test]
    fn removing_a_missing_artefact_caches_its_absence() {
        let storage = storage();
        let function = FunctionId::new(7);
        let mut staging = IlStaging::default();

        assert!(
            staging
                .remove::<PCodeIr>(&storage, function)
                .expect("missing artefact lookup should succeed")
                .is_none()
        );
        assert!(
            staging
                .remove::<PCodeIr>(&storage, function)
                .expect("cached missing artefact lookup should succeed")
                .is_none()
        );
    }

    #[test]
    fn an_override_key_round_trips_through_its_encoding() {
        let key = IlOverrideKey::new(FunctionId::new(9), PCodeIr::FORM);
        let mut encoded = Vec::new();
        key.encode(&mut encoded);
        let mut input = encoded.as_slice();

        assert_eq!(IlOverrideKey::decode(&mut input), Some(key));
        assert!(input.is_empty());
    }

    #[test]
    fn a_schema_mismatch_is_reported_rather_than_decoded() {
        let stored = IlOverride {
            form: String::from(PCodeIr::FORM_IDENTIFIER),
            schema: PCodeIr::SCHEMA.value().wrapping_add(1),
            input_revision: 0,
            bytes: Vec::new(),
        };

        assert!(matches!(
            stored.decode::<PCodeIr>(),
            Err(IlStorageError::Il(IlError::SchemaMismatch { .. }))
        ));
    }

    #[test]
    fn an_override_for_an_unregistered_form_reports_its_dialect_as_unavailable() {
        let stored = IlOverride {
            form: String::from("acme.taint.values"),
            schema: PCodeIr::SCHEMA.value(),
            input_revision: 0,
            bytes: Vec::new(),
        };

        assert!(matches!(
            stored.decode::<PCodeIr>(),
            Err(IlStorageError::Il(IlError::DialectUnavailable { .. }))
        ));
    }

    #[test]
    fn deleting_a_function_sweeps_every_stored_form_without_decoding() {
        let storage = storage();
        let function = FunctionId::new(7);
        let mut staging = IlStaging::default();

        staging
            .replace(&storage, pcode(function, Revision::from(1)))
            .expect("replacement should stage");
        let writes = staging.prepare().expect("staging should prepare");
        storage
            .entities()
            .apply_batch(&writes)
            .expect("writes should apply");

        let mut staging = IlStaging::default();
        assert_eq!(
            staging
                .remove_function(&storage, function)
                .expect("the sweep should succeed"),
            1
        );
        assert_eq!(
            staging
                .remove_function(&storage, FunctionId::new(8))
                .expect("an unrelated function has no overrides"),
            0
        );

        let mut swept = Vec::new();
        staging.for_each_change(|change| swept.push(change));
        assert_eq!(
            swept,
            vec![IlStagedChange::Removed {
                function,
                form: PCodeIr::FORM,
            }]
        );
    }
}
