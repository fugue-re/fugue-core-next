use fugue_core::ir::{Address as CoreAddress, RawAddress};
use fugue_core::storage::AddressSpaceId;
use pyo3::prelude::*;

use crate::address::Address;
use crate::errors::BindingError;

pub(crate) fn bytes_from_any(object: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let bytes = object
        .py()
        .import("builtins")?
        .getattr("bytes")?
        .call1((object,))?;
    bytes.extract()
}

pub(crate) fn address_space_id(index: usize) -> PyResult<AddressSpaceId> {
    AddressSpaceId::try_from(index).map_err(|_| BindingError::address_space(index).into())
}

pub(crate) fn address_from_parts(space: usize, offset: u64) -> PyResult<CoreAddress> {
    Ok(CoreAddress::new(
        address_space_id(space)?,
        RawAddress::new(offset),
    ))
}

pub(crate) fn address_from_any(
    object: &Bound<'_, PyAny>,
    default_space: usize,
) -> PyResult<CoreAddress> {
    if let Ok(address) = object.extract::<PyRef<'_, Address>>() {
        return Ok(address.inner());
    }

    let offset = object.extract::<u64>()?;
    address_from_parts(default_space, offset)
}

pub(crate) fn address_to_string(address: CoreAddress) -> String {
    address.to_string()
}
