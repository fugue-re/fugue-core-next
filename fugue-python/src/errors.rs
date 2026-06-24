use std::fmt::Display;

use fugue_core::ir::Address as CoreAddress;
use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use thiserror::Error;

create_exception!(fugue, FugueError, PyRuntimeError);
create_exception!(fugue, LoaderError, FugueError);
create_exception!(fugue, StorageError, FugueError);
create_exception!(fugue, LifterError, FugueError);

#[derive(Debug, Error)]
pub(crate) enum BindingError {
    #[error("address space index {0} out of range")]
    AddressSpace(usize),
    #[error("attribute key must be a string")]
    AttributeKey,
    #[error("attributes must be a dict")]
    AttributesNotDict,
    #[error("unsupported attribute value for `{0}`")]
    AttributeValue(String),
    #[error("empty byte mappings are not supported")]
    EmptyMapping,
    #[error("invalid instruction at {0}")]
    InvalidInstruction(CoreAddress),
    #[error("no mapped bytes at {0}")]
    NoMappedBytes(CoreAddress),
}

impl BindingError {
    pub(crate) fn address_space(index: usize) -> Self {
        Self::AddressSpace(index)
    }

    pub(crate) fn attribute_value(value: impl Into<String>) -> Self {
        Self::AttributeValue(value.into())
    }

    pub(crate) fn invalid_instruction(address: CoreAddress) -> Self {
        Self::InvalidInstruction(address)
    }

    pub(crate) fn no_mapped_bytes(address: CoreAddress) -> Self {
        Self::NoMappedBytes(address)
    }
}

impl From<BindingError> for PyErr {
    fn from(error: BindingError) -> Self {
        match error {
            BindingError::InvalidInstruction(_) => LifterError::new_err(error.to_string()),
            BindingError::NoMappedBytes(_) => StorageError::new_err(error.to_string()),
            BindingError::EmptyMapping
            | BindingError::AddressSpace(_)
            | BindingError::AttributesNotDict
            | BindingError::AttributeKey
            | BindingError::AttributeValue(_) => PyValueError::new_err(error.to_string()),
        }
    }
}

pub(crate) fn loader_error(error: impl Display) -> PyErr {
    LoaderError::new_err(error.to_string())
}

pub(crate) fn storage_error(error: impl Display) -> PyErr {
    StorageError::new_err(error.to_string())
}

pub(crate) fn lifter_error(error: impl Display) -> PyErr {
    LifterError::new_err(error.to_string())
}

pub(crate) fn add_errors(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("FugueError", module.py().get_type::<FugueError>())?;
    module.add("LoaderError", module.py().get_type::<LoaderError>())?;
    module.add("StorageError", module.py().get_type::<StorageError>())?;
    module.add("LifterError", module.py().get_type::<LifterError>())?;

    Ok(())
}
