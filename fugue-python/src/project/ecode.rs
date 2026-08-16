use super::*;

#[pyclass(frozen, skip_from_py_object)]
pub(crate) struct ECodeIr {
    pub(crate) inner: Arc<CoreECodeIr>,
}

impl ECodeIr {
    pub(crate) fn from_core(ir: Arc<CoreECodeIr>) -> Self {
        Self { inner: ir }
    }
}

#[pymethods]
impl ECodeIr {
    #[getter]
    fn form(&self) -> &'static str {
        <CoreECodeIr as IlArtefact>::FORM_IDENTIFIER
    }

    #[getter]
    fn schema(&self) -> u16 {
        <CoreECodeIr as PersistableIl>::SCHEMA.value()
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

    fn values(&self) -> Vec<ECodeValue> {
        self.inner
            .values()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, value)| {
                let id = CoreIlValueId::try_from_index(index)
                    .expect("ECode value index is representable");
                ECodeValue::from_core(index, value, self.inner.value_domain(id))
            })
            .collect()
    }

    pub(crate) fn value_uses(&self) -> PyResult<Vec<ECodeValueUses>> {
        let uses = self.inner.analyse::<CoreECodeUses>();
        self.inner
            .values()
            .iter()
            .enumerate()
            .map(|(value, _)| ECodeValueUses::from_core(&uses, value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    pub(crate) fn uses_for_value(&self, value: usize) -> PyResult<Vec<ECodeUse>> {
        let value = CoreIlValueId::try_from_index(value).map_err(project_error)?;
        let uses = self.inner.analyse::<CoreECodeUses>();

        Ok(uses
            .uses_for(value)
            .iter()
            .copied()
            .map(ECodeUse::from_core)
            .collect())
    }

    pub(crate) fn liveness(&self) -> PyResult<Vec<ECodeLiveness>> {
        let liveness = self.inner.analyse::<CoreECodeLiveness>();
        self.inner
            .graph()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| ECodeLiveness::from_core(&liveness, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    pub(crate) fn live_in(&self, block: usize) -> PyResult<Vec<usize>> {
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let liveness = self.inner.analyse::<CoreECodeLiveness>();

        Ok(liveness
            .live_in(block)
            .iter()
            .map(|value| value.index())
            .collect())
    }

    pub(crate) fn live_out(&self, block: usize) -> PyResult<Vec<usize>> {
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let liveness = self.inner.analyse::<CoreECodeLiveness>();

        Ok(liveness
            .live_out(block)
            .iter()
            .map(|value| value.index())
            .collect())
    }

    pub(crate) fn dominance(&self) -> PyResult<Vec<IlDominance>> {
        let dominance = self.inner.analyse::<CoreDominance>();
        let frontiers =
            dominance.frontiers(self.inner.graph().blocks(), self.inner.graph().successors());
        self.inner
            .graph()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| IlDominance::from_core(&dominance, &frontiers, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    pub(crate) fn dominance_frontier(&self, block: usize) -> PyResult<Vec<usize>> {
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let frontiers = self.inner.analyse::<CoreDominanceFrontier>();

        Ok(frontiers
            .frontier_for(block)
            .iter()
            .map(|frontier| frontier.index())
            .collect())
    }

    pub(crate) fn dominates(&self, dominator: usize, block: usize) -> PyResult<bool> {
        let dominator = CoreIlBlockId::try_from_index(dominator).map_err(project_error)?;
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let dominance = self.inner.analyse::<CoreDominance>();

        Ok(dominance.dominates(dominator, block))
    }

    fn block_args(&self) -> Vec<ECodeBlockArg> {
        self.inner
            .block_args()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, arg)| ECodeBlockArg::from_core(index, arg))
            .collect()
    }

    fn edge_args(&self) -> Vec<ECodeEdgeArgs> {
        self.inner
            .edge_args()
            .iter()
            .enumerate()
            .map(|(edge, _)| ECodeEdgeArgs::from_core(&self.inner, edge))
            .collect()
    }

    fn args_for_edge(&self, edge: usize) -> Vec<usize> {
        self.inner
            .args_for_edge(edge)
            .iter()
            .map(|arg| arg.index())
            .collect()
    }

    fn memory_domains(&self) -> Vec<ECodeMemoryDomain> {
        self.inner
            .memory_domains()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, domain)| ECodeMemoryDomain::from_core(index, domain))
            .collect()
    }

    fn operations(&self) -> Vec<ECodeOp> {
        self.inner
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| ECodeOp::from_core(&self.inner, index, operation))
            .collect()
    }

    fn operations_for_source(&self, address: &Address) -> Vec<ECodeOp> {
        self.inner
            .operations_for_source(address.inner())
            .map(|(index, operation)| ECodeOp::from_core(&self.inner, index.index(), operation))
            .collect()
    }

    fn __repr__(&self) -> String {
        let function = self.inner.metadata().function();
        format!("ECodeIr(function={function:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeValue {
    index: usize,
    width: u32,
    definition_kind: &'static str,
    definition_index: usize,
    domain: Option<ECodeDomain>,
}

impl ECodeValue {
    fn from_core(index: usize, value: CoreECodeValue, domain: Option<CoreECodeDomain>) -> Self {
        let (definition_kind, definition_index) = match value.definition() {
            CoreIlSsaDef::BlockArg(arg) => ("block_arg", arg.index()),
            CoreIlSsaDef::Operation(operation) => ("operation", operation.index()),
        };

        Self {
            index,
            width: value.width(),
            definition_kind,
            definition_index,
            domain: domain.map(ECodeDomain::from_core),
        }
    }
}

#[pymethods]
impl ECodeValue {
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
    fn domain(&self) -> Option<ECodeDomain> {
        self.domain
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Copy, Clone)]
pub(crate) struct ECodeDomain {
    kind: &'static str,
    storage: Option<u64>,
    address_space: Option<usize>,
}

impl ECodeDomain {
    fn from_core(domain: CoreECodeDomain) -> Self {
        match domain {
            CoreECodeDomain::Flag(storage) => Self {
                kind: "flag",
                storage: Some(storage.value()),
                address_space: None,
            },
            CoreECodeDomain::Memory(space) => Self {
                kind: "memory",
                storage: None,
                address_space: Some(space.index()),
            },
            CoreECodeDomain::Register(storage) => Self {
                kind: "register",
                storage: Some(storage.value()),
                address_space: None,
            },
        }
    }
}

#[pymethods]
impl ECodeDomain {
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind
    }

    #[getter]
    fn storage(&self) -> Option<u64> {
        self.storage
    }

    #[getter]
    fn address_space(&self) -> Option<usize> {
        self.address_space
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeValueUses {
    value: usize,
    uses: Vec<ECodeUse>,
}

impl ECodeValueUses {
    fn from_core(uses: &CoreECodeUses, value: usize) -> Result<Self, CoreIlError> {
        let value_id = CoreIlValueId::try_from_index(value)?;
        let uses = uses
            .uses_for(value_id)
            .iter()
            .copied()
            .map(ECodeUse::from_core)
            .collect();

        Ok(Self { value, uses })
    }
}

#[pymethods]
impl ECodeValueUses {
    #[getter]
    fn value(&self) -> usize {
        self.value
    }

    #[getter]
    fn uses(&self) -> Vec<ECodeUse> {
        self.uses.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeUse {
    user: usize,
    operand_index: usize,
}

impl ECodeUse {
    fn from_core(use_record: CoreECodeUse) -> Self {
        Self {
            user: use_record.user().index(),
            operand_index: use_record.operand_index(),
        }
    }
}

#[pymethods]
impl ECodeUse {
    #[getter]
    fn user(&self) -> usize {
        self.user
    }

    #[getter]
    fn operand_index(&self) -> usize {
        self.operand_index
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeLiveness {
    block: usize,
    live_in: Vec<usize>,
    live_out: Vec<usize>,
}

impl ECodeLiveness {
    fn from_core(liveness: &CoreECodeLiveness, block: usize) -> Result<Self, CoreIlError> {
        let block_id = CoreIlBlockId::try_from_index(block)?;
        let live_in = liveness
            .live_in(block_id)
            .iter()
            .map(|value| value.index())
            .collect();
        let live_out = liveness
            .live_out(block_id)
            .iter()
            .map(|value| value.index())
            .collect();

        Ok(Self {
            block,
            live_in,
            live_out,
        })
    }
}

#[pymethods]
impl ECodeLiveness {
    #[getter]
    fn block(&self) -> usize {
        self.block
    }

    #[getter]
    fn live_in(&self) -> Vec<usize> {
        self.live_in.clone()
    }

    #[getter]
    fn live_out(&self) -> Vec<usize> {
        self.live_out.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeBlockArg {
    index: usize,
    block: usize,
    value: usize,
    width: u32,
}

impl ECodeBlockArg {
    fn from_core(index: usize, arg: CoreECodeBlockArg) -> Self {
        Self {
            index,
            block: arg.block().index(),
            value: arg.value().index(),
            width: arg.width(),
        }
    }
}

#[pymethods]
impl ECodeBlockArg {
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
pub(crate) struct ECodeEdgeArgs {
    edge: usize,
    args: Vec<usize>,
}

impl ECodeEdgeArgs {
    fn from_core(ir: &CoreECodeIr, edge: usize) -> Self {
        let args = ir
            .args_for_edge(edge)
            .iter()
            .map(|arg| arg.index())
            .collect();

        Self { edge, args }
    }
}

#[pymethods]
impl ECodeEdgeArgs {
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
pub(crate) struct ECodeMemoryDomain {
    index: usize,
    address_space: usize,
}

impl ECodeMemoryDomain {
    fn from_core(index: usize, domain: CoreECodeMemoryDomain) -> Self {
        Self {
            index,
            address_space: domain.space().index(),
        }
    }
}

#[pymethods]
impl ECodeMemoryDomain {
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
pub(crate) struct ECodeOp {
    index: usize,
    opcode: &'static str,
    results: Vec<usize>,
    operands: Vec<usize>,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<usize>,
}

impl ECodeOp {
    fn from_core(ir: &CoreECodeIr, index: usize, operation: &CoreECodeOp) -> Self {
        let results = operation.results().start()..operation.results().end();
        let results = results.collect();
        let operands = ir
            .operation_operands_for(operation)
            .iter()
            .map(|operand| operand.index())
            .collect();

        Self {
            index,
            opcode: operation.opcode().mnemonic(),
            results,
            operands,
            width: operation.width(),
            immediate: operation.immediate(),
            address: operation.address().map(Address::from_core),
            address_space: operation.address_space().map(|space| space.index()),
        }
    }
}

#[pymethods]
impl ECodeOp {
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
