use fallible_iterator::FallibleIterator;
use fugue_core::ir::{Address as CoreAddress, SegmentProperties as CoreSegmentProperties};
use fugue_core::lifter::{ContextHint as CoreContextHint, ContextHintKind};
use fugue_core::loader::{Loadable, Loader as CoreLoader};
use fugue_core::storage::{
    InMemorySegmentStorage, SegmentMappingBuilder, SegmentStorage as CoreSegmentStorage,
};
use fugue_core::types::AttributeMap;
use pyo3::exceptions::PyOverflowError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::address::Address;
use crate::attributes::attribute_map_from_py;
use crate::binary::Binary;
use crate::convert::{address_from_any, bytes_from_any};
use crate::errors::{BindingError, loader_error, storage_error};

fn properties_from_bits(bits: u8) -> CoreSegmentProperties {
    CoreSegmentProperties::from_bits_truncate(bits)
}

fn context_kind_name(hint: &CoreContextHint) -> &'static str {
    match hint.kind() {
        ContextHintKind::Code(_) => "code",
        ContextHintKind::Data => "data",
    }
}

fn convert_context_hint(hint: &CoreContextHint) -> ContextHint {
    ContextHint {
        kind: context_kind_name(hint).to_owned(),
        bitness: hint.kind().bitness(),
        is_code: hint.is_code(),
        is_data: hint.is_data(),
        context: hint.context().map(|context| context.to_string()),
        text: hint.to_string(),
    }
}

pub(crate) fn segment_storage_from_loader(
    loader: &CoreLoader<'static>,
    attributes: &mut AttributeMap,
) -> PyResult<CoreSegmentStorage> {
    Ok(
        CoreSegmentStorage::from_loadable::<InMemorySegmentStorage>(loader, attributes)
            .map_err(storage_error)?
            .into_parts()
            .0,
    )
}

pub(crate) fn loadable_segments_from_loader(
    loader: &CoreLoader<'static>,
) -> PyResult<Vec<LoadableSegment>> {
    let mut attributes = AttributeMap::default();
    let (storage, resolution) =
        CoreSegmentStorage::from_loadable::<InMemorySegmentStorage>(loader, &mut attributes)
            .map_err(storage_error)?
            .into_parts();

    let mut segments = Vec::new();
    let mut image_segments = loader.image_segments();

    while let Some(segment) = image_segments.next().map_err(loader_error)? {
        let Some(address) = resolution.resolve_address(segment.address()) else {
            continue;
        };

        let view = storage
            .view_containing(address)
            .map_err(storage_error)?
            .bytes_from(address)
            .ok_or_else(|| BindingError::no_mapped_bytes(address))?;
        let chunks = view
            .chunks()
            .iter()
            .filter_map(|chunk| {
                let available = segment.size().saturating_sub(chunk.offset());
                let len = usize::try_from(available.min(chunk.bytes().len() as u64)).ok()?;
                (len != 0).then(|| LoadableSegmentChunk {
                    offset: chunk.offset(),
                    bytes: chunk.bytes()[..len].to_vec(),
                })
            })
            .collect();

        let mapping_hints = segment
            .mapping_hints()
            .iter()
            .map(|(hint_offset, hint)| MappingHint {
                address: Address::from_core(CoreAddress::new(address.space(), *hint_offset)),
                hint: convert_context_hint(hint),
            })
            .collect();

        let function_hints = segment
            .function_hints()
            .iter()
            .map(|hint_offset| Address::from_core(CoreAddress::new(address.space(), *hint_offset)))
            .collect();

        segments.push(LoadableSegment {
            name: segment.name().to_owned(),
            address: Address::from_core(address),
            size: segment.size(),
            properties: SegmentProperties::from_core(segment.properties()),
            chunks,
            mapping_hints,
            function_hints,
        });
    }

    Ok(segments)
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ContextHint {
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    bitness: Option<u32>,
    #[pyo3(get)]
    is_code: bool,
    #[pyo3(get)]
    is_data: bool,
    #[pyo3(get)]
    context: Option<String>,
    #[pyo3(get)]
    text: String,
}

#[pymethods]
impl ContextHint {
    fn __str__(&self) -> &str {
        &self.text
    }

    fn __repr__(&self) -> String {
        let kind = &self.kind;
        let bitness = self.bitness;
        format!("ContextHint(kind={kind:?}, bitness={bitness:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MappingHint {
    #[pyo3(get)]
    address: Address,
    #[pyo3(get)]
    hint: ContextHint,
}

#[pymethods]
impl MappingHint {
    fn __repr__(&self) -> String {
        let address = self.address.display_text();
        let hint = self.hint.__str__();
        format!("MappingHint(address={address}, hint={hint:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SegmentProperties {
    pub(crate) inner: CoreSegmentProperties,
}

impl SegmentProperties {
    pub(crate) fn from_core(inner: CoreSegmentProperties) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SegmentProperties {
    #[new]
    #[pyo3(signature = (read = true, write = true, execute = true, big_endian = false, uninitialised = false, external = false))]
    fn new(
        read: bool,
        write: bool,
        execute: bool,
        big_endian: bool,
        uninitialised: bool,
        external: bool,
    ) -> Self {
        let mut properties = CoreSegmentProperties::NONE;

        if read {
            properties |= CoreSegmentProperties::PERM_READ;
        }
        if write {
            properties |= CoreSegmentProperties::PERM_WRITE;
        }
        if execute {
            properties |= CoreSegmentProperties::PERM_EXECUTE;
        }
        if big_endian {
            properties |= CoreSegmentProperties::BIG_ENDIAN;
        }
        if uninitialised {
            properties |= CoreSegmentProperties::UNINITIALISED;
        }
        if external {
            properties |= CoreSegmentProperties::EXTERNAL;
        }

        Self::from_core(properties)
    }

    #[staticmethod]
    fn from_bits(bits: u8) -> Self {
        Self::from_core(properties_from_bits(bits))
    }

    #[staticmethod]
    fn all() -> Self {
        Self::from_core(CoreSegmentProperties::PERM_ALL)
    }

    #[getter]
    fn bits(&self) -> u8 {
        self.inner.bits()
    }

    #[getter]
    fn read(&self) -> bool {
        self.inner.is_readable()
    }

    #[getter]
    fn write(&self) -> bool {
        self.inner.is_writable()
    }

    #[getter]
    fn execute(&self) -> bool {
        self.inner.is_executable()
    }

    #[getter]
    fn big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }

    #[getter]
    fn uninitialised(&self) -> bool {
        self.inner.is_uninitialised()
    }

    #[getter]
    fn external(&self) -> bool {
        self.inner.is_external()
    }

    fn __repr__(&self) -> String {
        let bits = self.bits();
        format!("SegmentProperties(bits={bits:#04x})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct LoadableSegment {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    address: Address,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    properties: SegmentProperties,
    chunks: Vec<LoadableSegmentChunk>,
    #[pyo3(get)]
    mapping_hints: Vec<MappingHint>,
    #[pyo3(get)]
    function_hints: Vec<Address>,
}

#[derive(Clone)]
struct LoadableSegmentChunk {
    offset: u64,
    bytes: Vec<u8>,
}

impl LoadableSegment {
    fn from_mapped_bytes(
        name: impl Into<String>,
        address: Address,
        properties: SegmentProperties,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            size: bytes.len() as u64,
            properties,
            chunks: vec![LoadableSegmentChunk { offset: 0, bytes }],
            mapping_hints: Vec::new(),
            function_hints: Vec::new(),
        }
    }
}

#[pymethods]
impl LoadableSegment {
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> PyResult<Py<PyBytes>> {
        let size = usize::try_from(self.size)
            .map_err(|_| PyOverflowError::new_err("segment size exceeds platform limits"))?;
        let mut bytes = vec![0; size];
        for chunk in &self.chunks {
            let start = usize::try_from(chunk.offset)
                .map_err(|_| PyOverflowError::new_err("segment offset exceeds platform limits"))?;
            if start >= size {
                continue;
            }
            let end = start.saturating_add(chunk.bytes.len()).min(size);
            bytes[start..end].copy_from_slice(&chunk.bytes[..end - start]);
        }
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    fn __repr__(&self) -> String {
        let name = &self.name;
        let address = self.address.display_text();
        let size = self.size;
        format!("LoadableSegment(name={name:?}, address={address}, size={size})")
    }
}

#[pyclass(unsendable)]
pub(crate) struct SegmentStorage {
    pub(crate) inner: CoreSegmentStorage,
}

#[pymethods]
impl SegmentStorage {
    #[staticmethod]
    fn empty() -> Self {
        Self {
            inner: CoreSegmentStorage::empty(),
        }
    }

    #[staticmethod]
    #[pyo3(signature = (binary, attributes = None))]
    fn from_binary(binary: &Binary, attributes: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let mut attributes = attribute_map_from_py(attributes)?;
        let inner = segment_storage_from_loader(&binary.loader, &mut attributes)?;

        Ok(Self { inner })
    }

    #[pyo3(signature = (name, address, data, permissions = None, space = 0))]
    fn map_bytes(
        &mut self,
        name: &str,
        address: &Bound<'_, PyAny>,
        data: &Bound<'_, PyAny>,
        permissions: Option<PyRef<'_, SegmentProperties>>,
        space: usize,
    ) -> PyResult<LoadableSegment> {
        let bytes = bytes_from_any(data)?;
        if bytes.is_empty() {
            return Err(BindingError::EmptyMapping.into());
        }

        let start = address_from_any(address, space)?;
        let properties = permissions
            .as_ref()
            .map(|permissions| permissions.inner)
            .unwrap_or(CoreSegmentProperties::PERM_ALL);
        let provider = InMemorySegmentStorage::from_bytes(bytes.clone());
        let provider_id = self
            .inner
            .open_provider(provider, CoreSegmentProperties::PERM_ALL);
        let mapping_id = self
            .inner
            .create_mapping_from_builder(
                SegmentMappingBuilder::new(start, bytes.len() as u64, 0, provider_id)
                    .with_properties(properties)
                    .with_name(name),
            )
            .map_err(storage_error)?;

        self.inner
            .add_mapping_to_space_top(start.space(), mapping_id)
            .map_err(storage_error)?;

        Ok(LoadableSegment::from_mapped_bytes(
            name,
            Address::from_core(start),
            SegmentProperties::from_core(properties),
            bytes,
        ))
    }

    #[pyo3(signature = (address, size, space = 0))]
    fn read_bytes<'py>(
        &self,
        py: Python<'py>,
        address: &Bound<'_, PyAny>,
        size: usize,
        space: usize,
    ) -> PyResult<Py<PyBytes>> {
        let address = address_from_any(address, space)?;
        let mut bytes = vec![0u8; size];
        self.inner
            .read_bytes_exact(address, &mut bytes)
            .map_err(storage_error)?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    #[pyo3(signature = (address, data, space = 0))]
    fn write_bytes(
        &mut self,
        address: &Bound<'_, PyAny>,
        data: &Bound<'_, PyAny>,
        space: usize,
    ) -> PyResult<()> {
        let address = address_from_any(address, space)?;
        let bytes = bytes_from_any(data)?;
        self.inner
            .write_bytes_exact(address, &bytes)
            .map_err(storage_error)?;
        Ok(())
    }

    #[pyo3(signature = (address, space = 0))]
    fn contains(&self, address: &Bound<'_, PyAny>, space: usize) -> PyResult<bool> {
        Ok(self
            .inner
            .contains_segment(address_from_any(address, space)?))
    }
}

pub(crate) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<ContextHint>()?;
    module.add_class::<MappingHint>()?;
    module.add_class::<SegmentProperties>()?;
    module.add_class::<LoadableSegment>()?;
    module.add_class::<SegmentStorage>()?;

    Ok(())
}
