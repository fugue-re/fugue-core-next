use fugue_core::il::pcode::{Op as CoreOp, PCodeOp as CorePCodeOp, Varnode as CoreVarnode};
use fugue_core::ir::Address as CoreAddress;
use fugue_core::lifter::{Language as CoreLanguage, Lifter as CoreLifter};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::address::Address;
use crate::binary::Language;
use crate::convert::{address_from_any, bytes_from_any};
use crate::errors::{BindingError, lifter_error, storage_error};
use crate::segments::SegmentStorage;

fn varnode_kind(language: &'static CoreLanguage, varnode: CoreVarnode) -> &'static str {
    if varnode.is_invalid() {
        "invalid"
    } else if varnode.space() == language.register_space() {
        "register"
    } else if varnode.space() == language.constant_space() {
        "constant"
    } else if varnode.space() == language.unique_space() {
        "unique"
    } else if varnode.space() == language.default_space() {
        "memory"
    } else {
        "other"
    }
}

fn op_name(op: CoreOp) -> String {
    match op {
        CoreOp::UserOp(_, _) => "CALLOTHER".to_owned(),
        _ => op.to_string(),
    }
}

fn convert_varnode(language: &'static CoreLanguage, varnode: CoreVarnode) -> Varnode {
    let space = varnode.space();
    Varnode {
        space,
        space_name: language.space_name(space).map(str::to_owned),
        offset: varnode.offset(),
        size: varnode.size(),
        kind: varnode_kind(language, varnode).to_owned(),
        register_name: language.register_name(&varnode).map(str::to_owned),
        text: language.display(&varnode).to_string(),
    }
}

fn convert_pcode_op(language: &'static CoreLanguage, operation: &CorePCodeOp) -> PCodeOp {
    let space = operation.space();
    let user_op = operation.user_op();

    PCodeOp {
        op: op_name(operation.op()),
        inputs: operation
            .inputs()
            .iter()
            .copied()
            .map(|varnode| convert_varnode(language, varnode))
            .collect(),
        output: operation
            .output()
            .copied()
            .map(|varnode| convert_varnode(language, varnode)),
        space,
        space_name: space.and_then(|space| language.space_name(space).map(str::to_owned)),
        user_op,
        user_op_name: user_op.and_then(|id| language.user_op_by_id(id).map(str::to_owned)),
        text: operation.display(language).to_string(),
    }
}

fn convert_instruction(
    language: &'static CoreLanguage,
    address: CoreAddress,
    length: usize,
    operations: &[CorePCodeOp],
    disassembly: Option<String>,
) -> Instruction {
    let pcode = operations
        .iter()
        .map(|operation| convert_pcode_op(language, operation))
        .collect();

    Instruction {
        address: Address::from_core(address),
        length,
        next_address: Address::from_core(address + length),
        properties: 0,
        disassembly,
        pcode,
        text: language.display(&operations.to_vec()).to_string(),
    }
}

fn read_source_bytes(
    source: &Bound<'_, PyAny>,
    address: CoreAddress,
    max_bytes: usize,
) -> PyResult<Vec<u8>> {
    if let Ok(storage) = source.extract::<PyRef<'_, SegmentStorage>>() {
        let mut bytes = vec![0u8; max_bytes];
        let read = storage
            .inner
            .read_bytes(address, &mut bytes)
            .map_err(storage_error)?;

        if read == 0 {
            return Err(BindingError::no_mapped_bytes(address).into());
        }

        bytes.truncate(read);
        return Ok(bytes);
    }

    bytes_from_any(source)
}

#[pyclass(unsendable)]
pub(crate) struct Lifter {
    pub(crate) inner: CoreLifter,
}

#[pymethods]
impl Lifter {
    #[getter]
    fn language(&self) -> Language {
        Language {
            inner: self.inner.language(),
        }
    }

    #[pyo3(signature = (address, source, max_bytes = 16, space = 0))]
    fn disassemble(
        &mut self,
        address: &Bound<'_, PyAny>,
        source: &Bound<'_, PyAny>,
        max_bytes: usize,
        space: usize,
    ) -> PyResult<Instruction> {
        let address = address_from_any(address, space)?;
        let bytes = read_source_bytes(source, address, max_bytes)?;
        let mut disassembly = String::new();
        let Some(length) = self.inner.disassemble(address, &bytes, &mut disassembly) else {
            return Err(BindingError::invalid_instruction(address).into());
        };

        Ok(convert_instruction(
            self.inner.language(),
            address,
            length,
            &[],
            Some(disassembly),
        ))
    }

    #[pyo3(signature = (address, source, max_bytes = 16, space = 0))]
    fn lift(
        &mut self,
        address: &Bound<'_, PyAny>,
        source: &Bound<'_, PyAny>,
        max_bytes: usize,
        space: usize,
    ) -> PyResult<Instruction> {
        let address = address_from_any(address, space)?;
        let bytes = read_source_bytes(source, address, max_bytes)?;
        let mut operations = Vec::new();
        let length = self
            .inner
            .lift_into(address, &bytes, &mut operations)
            .map_err(lifter_error)?;
        Ok(convert_instruction(
            self.inner.language(),
            address,
            length,
            &operations,
            None,
        ))
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Instruction {
    #[pyo3(get)]
    address: Address,
    #[pyo3(get)]
    length: usize,
    #[pyo3(get)]
    next_address: Address,
    #[pyo3(get)]
    properties: u16,
    #[pyo3(get)]
    disassembly: Option<String>,
    #[pyo3(get)]
    pcode: Vec<PCodeOp>,
    #[pyo3(get)]
    text: String,
}

#[pymethods]
impl Instruction {
    fn __repr__(&self) -> String {
        let address = self.address.display_text();
        let length = self.length;
        format!("Instruction(address={address}, length={length})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PCodeOp {
    #[pyo3(get)]
    op: String,
    #[pyo3(get)]
    inputs: Vec<Varnode>,
    #[pyo3(get)]
    output: Option<Varnode>,
    #[pyo3(get)]
    space: Option<u8>,
    #[pyo3(get)]
    space_name: Option<String>,
    #[pyo3(get)]
    user_op: Option<u16>,
    #[pyo3(get)]
    user_op_name: Option<String>,
    #[pyo3(get)]
    text: String,
}

#[pymethods]
impl PCodeOp {
    fn __repr__(&self) -> String {
        let op = &self.op;
        let text = &self.text;
        format!("PCodeOp(op={op:?}, text={text:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Varnode {
    #[pyo3(get)]
    space: u8,
    #[pyo3(get)]
    space_name: Option<String>,
    #[pyo3(get)]
    offset: u64,
    #[pyo3(get)]
    size: usize,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    register_name: Option<String>,
    #[pyo3(get)]
    text: String,
}

#[pymethods]
impl Varnode {
    fn __repr__(&self) -> String {
        let space = self.space;
        let offset = self.offset;
        let size = self.size;
        format!("Varnode(space={space}, offset={offset:#x}, size={size})")
    }
}

pub(crate) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Lifter>()?;
    module.add_class::<Instruction>()?;
    module.add_class::<PCodeOp>()?;
    module.add_class::<Varnode>()?;

    Ok(())
}
