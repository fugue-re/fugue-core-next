use std::any::Any;
use std::collections::BTreeMap;

use thiserror::Error;

use crate::il::common::{IlError, IlFormId, PersistableIl};
use crate::ir::FunctionId;
use crate::storage::entities::schema::{
    ENTITY_IL_OVERRIDE_ID, ENTITY_KEY_IL_OVERRIDE_ID, Entity, EntityId, EntityKey, EntityKeyId,
};
use crate::storage::entities::{EntityWrite, EntityWriteBatch};
use crate::storage::{EntityStorageError, StorageContainer};
use crate::types::common::Revision;

const FUNCTION_KEY_SIZE: usize = 8;

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

impl EntityKey for IlOverrideKey {
    const ID: EntityKeyId = ENTITY_KEY_IL_OVERRIDE_ID;

    fn decode(buf: &[u8]) -> Option<Self> {
        let (function, form) = buf.split_at_checked(FUNCTION_KEY_SIZE)?;
        Some(Self {
            function: FunctionId::decode(function)?,
            form: IlFormId::from_stored(str::from_utf8(form).ok()?),
        })
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        EntityKey::encode(&self.function, output);
        output.extend(self.form.as_str().bytes());
    }
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

struct IlStagedArtefact {
    artefact: Box<dyn Any + Send + Sync>,
    encode: IlEncodeFn,
}

struct IlMutation {
    base_present: bool,
    value: Option<IlStagedArtefact>,
}

#[derive(Default)]
pub(crate) struct IlStage {
    mutations: BTreeMap<IlOverrideKey, IlMutation>,
    stored: Option<BTreeMap<FunctionId, Vec<IlFormId>>>,
}

impl IlStage {
    pub(crate) fn replace<T>(
        &mut self,
        storage: &StorageContainer,
        artefact: T,
    ) -> Result<(), EntityStorageError>
    where
        T: PersistableIl,
    {
        let key = IlOverrideKey::new(artefact.metadata().function(), T::FORM);
        let staged = IlStagedArtefact {
            artefact: Box::new(artefact),
            encode: encode_erased::<T>,
        };
        if let Some(mutation) = self.mutations.get_mut(&key) {
            mutation.value = Some(staged);
            return Ok(());
        }

        let base_present = storage.contains_entity::<IlOverrideKey, IlOverride>(&key)?;
        self.mutations.insert(
            key,
            IlMutation {
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
        if let Some(mutation) = self.mutations.get_mut(&key) {
            return Ok(mutation.value.take().and_then(|staged| {
                staged
                    .artefact
                    .downcast::<T>()
                    .ok()
                    .map(|artefact| *artefact)
            }));
        }

        let previous = T::load(storage, function)?;
        self.mutations.insert(
            key,
            IlMutation {
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
        if let Some(mutation) = self.mutations.get_mut(&key) {
            return Ok(mutation.value.take().is_some());
        }

        let base_present = storage.contains_entity::<IlOverrideKey, IlOverride>(&key)?;
        self.mutations.insert(
            key,
            IlMutation {
                base_present,
                value: None,
            },
        );
        Ok(base_present)
    }

    pub(crate) fn prepare(&self) -> Result<EntityWriteBatch, EntityStorageError> {
        let mut writes = EntityWriteBatch::with_capacity(self.mutations.len());
        for (key, mutation) in &self.mutations {
            if !mutation.base_present && mutation.value.is_none() {
                continue;
            }
            let key = IlOverride::ID.key_for(key);
            writes.push(match &mutation.value {
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
            let mut stored: BTreeMap<FunctionId, Vec<IlFormId>> = BTreeMap::new();
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
                .mutations
                .insert(
                    IlOverrideKey::new(function, form.clone()),
                    IlMutation {
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

    pub(crate) fn for_each_change(&self, mut f: impl FnMut(FunctionId, IlFormId, bool)) {
        for (key, mutation) in &self.mutations {
            if mutation.base_present || mutation.value.is_some() {
                f(key.function(), key.form().clone(), mutation.value.is_some());
            }
        }
    }
}

#[cfg(test)]
mod test;
