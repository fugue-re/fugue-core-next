use fugue_core::ir::Address as CoreAddress;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::convert::{address_from_parts, address_to_string};

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Address {
    inner: CoreAddress,
}

impl Address {
    pub(crate) fn from_core(inner: CoreAddress) -> Self {
        Self { inner }
    }

    pub(crate) fn display_text(&self) -> String {
        address_to_string(self.inner)
    }

    pub(crate) fn inner(&self) -> CoreAddress {
        self.inner
    }
}

#[pymethods]
impl Address {
    #[new]
    #[pyo3(signature = (offset, space = 0))]
    fn new(offset: u64, space: usize) -> PyResult<Self> {
        Ok(Self::from_core(address_from_parts(space, offset)?))
    }

    #[getter]
    fn space(&self) -> usize {
        self.inner.space().index()
    }

    #[getter]
    fn offset(&self) -> u64 {
        self.inner.address().offset()
    }

    fn __str__(&self) -> String {
        self.display_text()
    }

    fn __repr__(&self) -> String {
        let offset = self.offset();
        let space = self.space();
        format!("Address(offset={offset:#x}, space={space})")
    }
}

pub(crate) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Address>()?;

    Ok(())
}
