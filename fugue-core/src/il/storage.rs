use thiserror::Error;

use crate::il::common::{IlArtefact, IlError};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::ir::FunctionId;
use crate::storage::entities::{EntityStorage, EntityStorageError};

#[derive(Debug, Error)]
pub(crate) enum IlStorageError {
    #[error(transparent)]
    Il(#[from] IlError),
    #[error(transparent)]
    Storage(#[from] EntityStorageError),
}

pub(crate) trait IlPersist: IlArtefact + Sized {
    fn load(
        entities: &EntityStorage,
        function: FunctionId,
    ) -> Result<Option<Self>, IlStorageError> {
        let Some(artefact) = entities.get::<FunctionId, Self>(&function)? else {
            return Ok(None);
        };

        if artefact.header().schema() != Self::SCHEMA {
            return Err(IlError::schema_mismatch(
                Self::LEVEL,
                Self::SCHEMA.value(),
                artefact.header().schema().value(),
            )
            .into());
        }

        Ok(Some(artefact))
    }

    fn load_current(
        entities: &EntityStorage,
        function: FunctionId,
        input_revision: u64,
    ) -> Result<Option<Self>, IlStorageError> {
        let Some(artefact) = Self::load(entities, function)? else {
            return Ok(None);
        };

        if artefact.header().input_revision() != input_revision {
            return Err(IlError::stale_artefact(
                Self::LEVEL,
                input_revision,
                artefact.header().input_revision(),
            )
            .into());
        }

        Ok(Some(artefact))
    }

    fn persist(&self, entities: &EntityStorage) -> Result<IlRevert, EntityStorageError>
    where
        IlRevert: From<(FunctionId, Option<Self>)>,
    {
        let function = self.header().function();
        let previous = entities.get::<FunctionId, Self>(&function)?;

        entities.insert(&function, self)?;

        Ok(IlRevert::from((function, previous)))
    }

    fn remove(
        entities: &EntityStorage,
        function: FunctionId,
    ) -> Result<Option<(Self, IlRevert)>, EntityStorageError>
    where
        Self: Clone,
        IlRevert: From<(FunctionId, Option<Self>)>,
    {
        let Some(previous) = entities.get::<FunctionId, Self>(&function)? else {
            return Ok(None);
        };

        entities.remove::<FunctionId, Self>(&function)?;

        Ok(Some((
            previous.clone(),
            IlRevert::from((function, Some(previous))),
        )))
    }
}

impl<T: IlArtefact> IlPersist for T {}

pub(crate) enum IlRevert {
    PCode(FunctionId, Option<PCodeIr>),
    ECode(FunctionId, Option<ECodeIr>),
    ECodeSsa(FunctionId, Option<ECodeSsaIr>),
}

impl From<(FunctionId, Option<PCodeIr>)> for IlRevert {
    fn from((function, previous): (FunctionId, Option<PCodeIr>)) -> Self {
        Self::PCode(function, previous)
    }
}

impl From<(FunctionId, Option<ECodeIr>)> for IlRevert {
    fn from((function, previous): (FunctionId, Option<ECodeIr>)) -> Self {
        Self::ECode(function, previous)
    }
}

impl From<(FunctionId, Option<ECodeSsaIr>)> for IlRevert {
    fn from((function, previous): (FunctionId, Option<ECodeSsaIr>)) -> Self {
        Self::ECodeSsa(function, previous)
    }
}

impl IlRevert {
    pub(crate) fn restore(self, entities: &EntityStorage) -> Result<(), EntityStorageError> {
        fn restore_one<T>(
            entities: &EntityStorage,
            function: FunctionId,
            previous: Option<T>,
        ) -> Result<(), EntityStorageError>
        where
            T: IlArtefact,
        {
            match previous {
                Some(artefact) => entities.insert(&function, &artefact),
                None => entities.remove::<FunctionId, T>(&function),
            }
        }

        match self {
            Self::PCode(function, previous) => restore_one(entities, function, previous),
            Self::ECode(function, previous) => restore_one(entities, function, previous),
            Self::ECodeSsa(function, previous) => restore_one(entities, function, previous),
        }
    }
}
