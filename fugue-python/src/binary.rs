use std::path::PathBuf;

use fugue_core::arch::Arch as CoreArch;
use fugue_core::il::pcode::Varnode as CoreVarnode;
use fugue_core::lifter::Language as CoreLanguage;
use fugue_core::loader::{Loadable, Loader as CoreLoader};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::attributes::attribute_map_from_py;
use crate::convert::bytes_from_any;
use crate::errors::loader_error;
use crate::lifter::Lifter;
use crate::segments::{LoadableSegment, loadable_segments_from_loader};

#[pyclass(unsendable)]
pub(crate) struct Binary {
    pub(crate) loader: CoreLoader<'static>,
}

#[pymethods]
impl Binary {
    #[staticmethod]
    #[pyo3(signature = (data, attributes = None))]
    fn from_bytes(
        data: &Bound<'_, PyAny>,
        attributes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let bytes = bytes_from_any(data)?;
        let loader = CoreLoader::new_with(bytes, attribute_map_from_py(attributes)?)
            .map_err(loader_error)?;
        Ok(Self { loader })
    }

    #[staticmethod]
    #[pyo3(signature = (path, attributes = None))]
    fn from_file(path: PathBuf, attributes: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let loader = CoreLoader::from_file_with(path, attribute_map_from_py(attributes)?)
            .map_err(loader_error)?;
        Ok(Self { loader })
    }

    #[getter]
    fn architecture(&self) -> Architecture {
        Architecture {
            inner: self.loader.architecture(),
        }
    }

    #[getter]
    fn language(&self) -> Language {
        Language {
            inner: self.loader.architecture().language(),
        }
    }

    fn lifter(&self) -> Lifter {
        Lifter {
            inner: self.loader.architecture().lifter(),
        }
    }

    fn segments(&self) -> PyResult<Vec<LoadableSegment>> {
        loadable_segments_from_loader(&self.loader)
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Language {
    pub(crate) inner: &'static CoreLanguage,
}

#[pymethods]
impl Language {
    #[getter]
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    #[getter]
    fn processor(&self) -> &'static str {
        self.inner.processor()
    }

    #[getter]
    fn variant(&self) -> &'static str {
        self.inner.variant()
    }

    #[getter]
    fn big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }

    #[getter]
    fn little_endian(&self) -> bool {
        self.inner.is_little_endian()
    }

    #[getter]
    fn address_alignment(&self) -> usize {
        self.inner.address_alignment()
    }

    #[getter]
    fn address_bits(&self) -> u32 {
        self.inner.address_bits()
    }

    #[getter]
    fn address_size(&self) -> usize {
        self.inner.address_size()
    }

    #[getter]
    fn default_space(&self) -> u8 {
        self.inner.default_space()
    }

    #[getter]
    fn register_space(&self) -> u8 {
        self.inner.register_space()
    }

    #[getter]
    fn unique_space(&self) -> u8 {
        self.inner.unique_space()
    }

    fn space_name(&self, space: u8) -> Option<&'static str> {
        self.inner.space_name(space)
    }

    fn register_name(&self, space: u8, offset: u64, size: u16) -> Option<&'static str> {
        self.inner
            .register_name(&CoreVarnode::new(space, offset, size))
    }

    fn __str__(&self) -> &'static str {
        self.inner.id()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Architecture {
    inner: CoreArch,
}

#[pymethods]
impl Architecture {
    #[getter]
    fn language(&self) -> Language {
        Language {
            inner: self.inner.language(),
        }
    }

    #[getter]
    fn endian(&self) -> String {
        self.inner.endian().to_string()
    }

    fn lifter(&self) -> Lifter {
        Lifter {
            inner: self.inner.lifter(),
        }
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

pub(crate) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Binary>()?;
    module.add_class::<Language>()?;
    module.add_class::<Architecture>()?;

    Ok(())
}
