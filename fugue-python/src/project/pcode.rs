use super::*;

#[pyclass(frozen, skip_from_py_object)]
pub(crate) struct PCodeIr {
    pub(crate) inner: Arc<CorePCodeIr>,
}

impl PCodeIr {
    pub(crate) fn from_core(ir: Arc<CorePCodeIr>) -> Self {
        Self { inner: ir }
    }
}

#[pymethods]
impl PCodeIr {
    #[getter]
    fn form(&self) -> &'static str {
        <CorePCodeIr as IlArtefact>::FORM_IDENTIFIER
    }

    #[getter]
    fn schema(&self) -> u16 {
        <CorePCodeIr as PersistableIl>::SCHEMA.value()
    }

    fn metadata(&self) -> IlMetadata {
        IlMetadata::from_core(*self.inner.metadata())
    }

    fn graph(&self) -> IlGraph {
        IlGraph::from_core(self.inner.graph().clone())
    }

    fn source_spans(&self) -> Vec<IlSourceSpan> {
        self.inner
            .source_spans()
            .iter()
            .copied()
            .map(IlSourceSpan::from_core)
            .collect()
    }

    fn source_span_for(&self, node: usize) -> Option<IlSourceSpan> {
        self.inner
            .source_span_for(node)
            .map(IlSourceSpan::from_core)
    }

    fn source_spans_for(&self, address: &Address, pcode_index: u32) -> Vec<IlSourceSpan> {
        self.inner
            .source_spans_for(address.inner(), pcode_index)
            .map(IlSourceSpan::from_core)
            .collect()
    }

    fn locations(&self) -> Vec<PCodeLocation> {
        self.inner
            .locations()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, location)| PCodeLocation::from_core(index, location))
            .collect()
    }

    fn operations(&self) -> Vec<PCodeOp> {
        self.inner
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| PCodeOp::from_core(&self.inner, index, operation))
            .collect()
    }

    fn operations_for_source(&self, address: &Address) -> Vec<PCodeOp> {
        self.inner
            .operations_for_source(address.inner())
            .map(|(index, operation)| PCodeOp::from_core(&self.inner, index.index(), operation))
            .collect()
    }

    fn display_source(&self, address: &Address) -> String {
        self.inner.display_source(address.inner()).to_string()
    }

    fn __repr__(&self) -> String {
        let function = self.inner.metadata().function();
        format!("PCodeIr(function={function:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PCodeLocation {
    index: usize,
    lifter_space: u8,
    offset: u64,
    size: u16,
    constant: bool,
    register: bool,
    unique: bool,
}

impl PCodeLocation {
    fn from_core(index: usize, location: CorePCodeLocation) -> Self {
        Self {
            index,
            lifter_space: location.lifter_space().value(),
            offset: location.offset(),
            size: location.size(),
            constant: location.is_constant(),
            register: location.is_register(),
            unique: location.is_unique(),
        }
    }
}

#[pymethods]
impl PCodeLocation {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn lifter_space(&self) -> u8 {
        self.lifter_space
    }

    #[getter]
    fn offset(&self) -> u64 {
        self.offset
    }

    #[getter]
    fn size(&self) -> u16 {
        self.size
    }

    #[getter]
    fn constant(&self) -> bool {
        self.constant
    }

    #[getter]
    fn register(&self) -> bool {
        self.register
    }

    #[getter]
    fn unique(&self) -> bool {
        self.unique
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PCodeOp {
    index: usize,
    opcode: &'static str,
    operands: Vec<usize>,
    output: Option<usize>,
    immediate: u32,
    address_space: Option<usize>,
    target: Option<Address>,
}

impl PCodeOp {
    fn from_core(ir: &CorePCodeIr, index: usize, operation: &CorePCodeOp) -> Self {
        let operands = ir
            .operation_operands_for(operation)
            .iter()
            .map(|operand| operand.index())
            .collect();
        let target = if matches!(
            operation.opcode(),
            CorePCodeOpcode::Branch | CorePCodeOpcode::CBranch | CorePCodeOpcode::Call
        ) {
            operation
                .target()
                .and_then(|target| ir.target(target))
                .map(|target| Address::from_core(target.address()))
        } else {
            None
        };

        Self {
            index,
            opcode: operation.opcode().mnemonic(),
            operands,
            output: operation.output().map(|output| output.index()),
            immediate: operation.immediate(),
            address_space: operation.address_space().map(|space| space.index()),
            target,
        }
    }
}

#[pymethods]
impl PCodeOp {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn opcode(&self) -> &'static str {
        self.opcode
    }

    #[getter]
    fn operands(&self) -> Vec<usize> {
        self.operands.clone()
    }

    #[getter]
    fn output(&self) -> Option<usize> {
        self.output
    }

    #[getter]
    fn immediate(&self) -> u32 {
        self.immediate
    }

    #[getter]
    fn address_space(&self) -> Option<usize> {
        self.address_space
    }

    #[getter]
    fn target(&self) -> Option<Address> {
        self.target.clone()
    }
}
