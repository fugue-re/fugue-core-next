use super::*;

#[pyclass(frozen, skip_from_py_object)]
pub(crate) struct MCodeIr {
    pub(crate) inner: Arc<CoreMCodeIr>,
}

impl MCodeIr {
    pub(crate) fn from_core(ir: Arc<CoreMCodeIr>) -> Self {
        Self { inner: ir }
    }
}

#[pymethods]
impl MCodeIr {
    #[getter]
    fn form(&self) -> &'static str {
        <CoreMCodeIr as IlArtefact>::FORM_IDENTIFIER
    }

    #[getter]
    fn schema(&self) -> u16 {
        <CoreMCodeIr as PersistableIl>::SCHEMA.value()
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

    fn parent_spans(&self) -> Vec<IlParentSpan> {
        self.inner
            .parent_spans()
            .iter()
            .copied()
            .map(IlParentSpan::from_core)
            .collect()
    }

    fn source_span_for(&self, node: usize) -> Option<IlSourceSpan> {
        self.inner
            .source_span_for(node)
            .map(IlSourceSpan::from_core)
    }

    fn parent_span_for(&self, node: usize) -> Option<IlParentSpan> {
        self.inner
            .parent_span_for(node)
            .map(IlParentSpan::from_core)
    }

    fn variables(&self) -> Vec<MCodeVar> {
        self.inner
            .variables()
            .iter()
            .copied()
            .enumerate()
            .map(|(id, variable)| {
                let variable_id = CoreMCodeVarId::try_from_index(id)
                    .expect("MCode variable index is representable");
                MCodeVar::from_core(id, variable, self.inner.is_aliased(variable_id))
            })
            .collect()
    }

    fn aliased_variables(&self) -> Vec<usize> {
        self.inner
            .aliased_variables()
            .iter()
            .map(|variable| variable.index())
            .collect()
    }

    fn values(&self) -> Vec<MCodeValue> {
        self.inner
            .values()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, value)| MCodeValue::from_core(index, value))
            .collect()
    }

    fn block_args(&self) -> Vec<MCodeBlockArg> {
        self.inner
            .block_args()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, arg)| MCodeBlockArg::from_core(index, arg))
            .collect()
    }

    fn edge_args(&self) -> Vec<MCodeEdgeArgs> {
        self.inner
            .edge_args()
            .iter()
            .enumerate()
            .map(|(edge, _)| MCodeEdgeArgs::from_core(&self.inner, edge))
            .collect()
    }

    fn args_for_edge(&self, edge: usize) -> Vec<usize> {
        self.inner
            .args_for_edge(edge)
            .iter()
            .map(|arg| arg.index())
            .collect()
    }

    fn memory_domains(&self) -> Vec<MCodeMemoryDomain> {
        self.inner
            .memory_domains()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, domain)| MCodeMemoryDomain::from_core(index, domain))
            .collect()
    }

    fn operations(&self) -> Vec<MCodeOp> {
        self.inner
            .ops()
            .iter()
            .enumerate()
            .map(|(index, operation)| MCodeOp::from_core(&self.inner, index, operation))
            .collect()
    }

    fn operations_for_source(&self, address: &Address) -> Vec<MCodeOp> {
        self.inner
            .ops_for_source(address.inner())
            .map(|(index, operation)| MCodeOp::from_core(&self.inner, index.index(), operation))
            .collect()
    }

    fn __repr__(&self) -> String {
        let function = self.inner.metadata().function();
        format!("MCodeIr(function={function:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MCodeVar {
    id: usize,
    kind: &'static str,
    flag: Option<u64>,
    register: Option<u64>,
    stack_offset: Option<i64>,
    index: u32,
    aliased: bool,
}

impl MCodeVar {
    fn from_core(id: usize, variable: CoreMCodeVar, aliased: bool) -> Self {
        let kind = match variable.kind() {
            CoreMCodeVarKind::Flag => "flag",
            CoreMCodeVarKind::Register => "register",
            CoreMCodeVarKind::Stack => "stack",
        };
        Self {
            id,
            kind,
            flag: variable.flag_id().map(|flag| flag.value()),
            register: variable.register_id().map(|register| register.value()),
            stack_offset: variable.stack_offset(),
            index: variable.index(),
            aliased,
        }
    }
}

#[pymethods]
impl MCodeVar {
    #[getter]
    fn id(&self) -> usize {
        self.id
    }

    #[getter]
    fn kind(&self) -> &'static str {
        self.kind
    }

    #[getter]
    fn flag(&self) -> Option<u64> {
        self.flag
    }

    #[getter]
    fn register(&self) -> Option<u64> {
        self.register
    }

    #[getter]
    fn stack_offset(&self) -> Option<i64> {
        self.stack_offset
    }

    #[getter]
    fn index(&self) -> u32 {
        self.index
    }

    #[getter]
    fn aliased(&self) -> bool {
        self.aliased
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MCodeValue {
    index: usize,
    width: u32,
    definition_kind: &'static str,
    definition_index: usize,
    variable: Option<usize>,
    version: u32,
}

impl MCodeValue {
    fn from_core(index: usize, value: CoreMCodeValue) -> Self {
        let (definition_kind, definition_index) = match value.definition() {
            CoreIlSsaDef::BlockArg(arg) => ("block_arg", arg.index()),
            CoreIlSsaDef::Op(operation) => ("operation", operation.index()),
        };
        let binding = value.binding();
        Self {
            index,
            width: value.width(),
            definition_kind,
            definition_index,
            variable: binding.map(|binding| binding.variable().index()),
            version: binding.map_or(0, |binding| binding.version().value()),
        }
    }
}

#[pymethods]
impl MCodeValue {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn width(&self) -> u32 {
        self.width
    }

    #[getter]
    fn definition_kind(&self) -> &'static str {
        self.definition_kind
    }

    #[getter]
    fn definition_index(&self) -> usize {
        self.definition_index
    }

    #[getter]
    fn variable(&self) -> Option<usize> {
        self.variable
    }

    #[getter]
    fn version(&self) -> u32 {
        self.version
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MCodeBlockArg {
    index: usize,
    block: usize,
    value: usize,
    width: u32,
}

impl MCodeBlockArg {
    fn from_core(index: usize, arg: CoreMCodeBlockArg) -> Self {
        Self {
            index,
            block: arg.block().index(),
            value: arg.value().index(),
            width: arg.width(),
        }
    }
}

#[pymethods]
impl MCodeBlockArg {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn block(&self) -> usize {
        self.block
    }

    #[getter]
    fn value(&self) -> usize {
        self.value
    }

    #[getter]
    fn width(&self) -> u32 {
        self.width
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MCodeEdgeArgs {
    edge: usize,
    args: Vec<usize>,
}

impl MCodeEdgeArgs {
    fn from_core(ir: &CoreMCodeIr, edge: usize) -> Self {
        let args = ir
            .args_for_edge(edge)
            .iter()
            .map(|arg| arg.index())
            .collect();
        Self { edge, args }
    }
}

#[pymethods]
impl MCodeEdgeArgs {
    #[getter]
    fn edge(&self) -> usize {
        self.edge
    }

    #[getter]
    fn args(&self) -> Vec<usize> {
        self.args.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MCodeMemoryDomain {
    index: usize,
    address_space: usize,
}

impl MCodeMemoryDomain {
    fn from_core(index: usize, domain: CoreMCodeMemoryDomain) -> Self {
        Self {
            index,
            address_space: domain.space().index(),
        }
    }
}

#[pymethods]
impl MCodeMemoryDomain {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn address_space(&self) -> usize {
        self.address_space
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MCodeOp {
    index: usize,
    opcode: &'static str,
    results: Vec<usize>,
    operands: Vec<usize>,
    width: u32,
    variable: Option<usize>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<usize>,
}

impl MCodeOp {
    fn from_core(ir: &CoreMCodeIr, index: usize, operation: &CoreMCodeOp) -> Self {
        let results = (operation.results().start()..operation.results().end()).collect();
        let operands = ir
            .op_operands_for(operation)
            .iter()
            .map(|operand| operand.index())
            .collect();
        Self {
            index,
            opcode: operation.opcode().mnemonic(),
            results,
            operands,
            width: operation.width(),
            variable: operation.variable().map(|variable| variable.index()),
            immediate: operation.immediate(),
            address: operation.address().map(Address::from_core),
            address_space: operation.address_space().map(|space| space.index()),
        }
    }
}

#[pymethods]
impl MCodeOp {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn opcode(&self) -> &'static str {
        self.opcode
    }

    #[getter]
    fn results(&self) -> Vec<usize> {
        self.results.clone()
    }

    #[getter]
    fn operands(&self) -> Vec<usize> {
        self.operands.clone()
    }

    #[getter]
    fn width(&self) -> u32 {
        self.width
    }

    #[getter]
    fn variable(&self) -> Option<usize> {
        self.variable
    }

    #[getter]
    fn immediate(&self) -> u64 {
        self.immediate
    }

    #[getter]
    fn address(&self) -> Option<Address> {
        self.address.clone()
    }

    #[getter]
    fn address_space(&self) -> Option<usize> {
        self.address_space
    }
}
