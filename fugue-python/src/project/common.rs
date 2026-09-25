use super::*;

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlMetadata {
    inner: CoreIlMetadata,
}

impl IlMetadata {
    pub(crate) fn from_core(metadata: CoreIlMetadata) -> Self {
        Self { inner: metadata }
    }
}

#[pymethods]
impl IlMetadata {
    #[getter]
    fn function(&self) -> String {
        let function = self.inner.function();
        format!("{function:x}")
    }

    #[getter]
    fn input_revision(&self) -> u64 {
        self.inner.input_revision().value()
    }

    fn __repr__(&self) -> String {
        let function = self.function();
        let input_revision = self.input_revision();
        format!("IlMetadata(function={function:?}, input_revision={input_revision})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
pub(crate) struct IlGraph {
    inner: CoreIlGraph,
}

impl IlGraph {
    pub(crate) fn from_core(common: CoreIlGraph) -> Self {
        Self { inner: common }
    }
}

#[pymethods]
impl IlGraph {
    fn blocks(&self) -> Vec<IlBlock> {
        let successors = self.inner.successors();
        self.inner
            .blocks()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, block)| IlBlock::from_core(index, block, successors))
            .collect()
    }

    fn successors(&self) -> Vec<usize> {
        self.inner
            .successors()
            .iter()
            .map(|successor| successor.index())
            .collect()
    }

    fn predecessors(&self) -> PyResult<Vec<IlBlockPredecessors>> {
        let predecessors =
            CoreIlBlockPredecessors::new(self.inner.blocks(), self.inner.successors());

        self.inner
            .blocks()
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let block = CoreIlBlockId::try_from_index(index)?;
                Ok(IlBlockPredecessors::from_core(
                    index,
                    predecessors.predecessors_for(block),
                ))
            })
            .collect::<Result<Vec<_>, CoreIlError>>()
            .map_err(project_error)
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlBlock {
    index: usize,
    operation_start: usize,
    operation_end: usize,
    successor_start: usize,
    successor_end: usize,
    successors: Vec<usize>,
    properties: u16,
}

impl IlBlock {
    fn from_core(index: usize, block: CoreIlBlock, successors: &[CoreIlBlockId]) -> Self {
        let successors = block
            .successors()
            .slice(successors)
            .iter()
            .map(|successor| successor.index())
            .collect();

        Self {
            index,
            operation_start: block.ops().start(),
            operation_end: block.ops().end(),
            successor_start: block.successors().start(),
            successor_end: block.successors().end(),
            successors,
            properties: block.properties().bits(),
        }
    }
}

#[pymethods]
impl IlBlock {
    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn operation_start(&self) -> usize {
        self.operation_start
    }

    #[getter]
    fn operation_end(&self) -> usize {
        self.operation_end
    }

    #[getter]
    fn successor_start(&self) -> usize {
        self.successor_start
    }

    #[getter]
    fn successor_end(&self) -> usize {
        self.successor_end
    }

    #[getter]
    fn successors(&self) -> Vec<usize> {
        self.successors.clone()
    }

    #[getter]
    fn properties(&self) -> u16 {
        self.properties
    }

    #[getter]
    fn entry(&self) -> bool {
        CoreIlBlockProperties::from_bits_retain(self.properties)
            .contains(CoreIlBlockProperties::ENTRY)
    }

    #[getter]
    fn exit(&self) -> bool {
        CoreIlBlockProperties::from_bits_retain(self.properties)
            .contains(CoreIlBlockProperties::EXIT)
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlBlockPredecessors {
    block: usize,
    predecessors: Vec<usize>,
}

impl IlBlockPredecessors {
    fn from_core(block: usize, predecessors: &[CoreIlBlockId]) -> Self {
        Self {
            block,
            predecessors: predecessors
                .iter()
                .map(|predecessor| predecessor.index())
                .collect(),
        }
    }
}

#[pymethods]
impl IlBlockPredecessors {
    #[getter]
    fn block(&self) -> usize {
        self.block
    }

    #[getter]
    fn predecessors(&self) -> Vec<usize> {
        self.predecessors.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlSourceSpan {
    address: Address,
    destination_start: usize,
    destination_end: usize,
    first_source_index: u32,
    source_count: u32,
}

impl IlSourceSpan {
    pub(crate) fn from_core(span: CoreIlSourceSpan) -> Self {
        Self {
            address: Address::from_core(span.address()),
            destination_start: span.destination().start(),
            destination_end: span.destination().end(),
            first_source_index: span.first_source_index(),
            source_count: span.source_count(),
        }
    }
}

#[pymethods]
impl IlSourceSpan {
    #[getter]
    fn address(&self) -> Address {
        self.address.clone()
    }

    #[getter]
    fn destination_start(&self) -> usize {
        self.destination_start
    }

    #[getter]
    fn destination_end(&self) -> usize {
        self.destination_end
    }

    #[getter]
    fn first_source_index(&self) -> u32 {
        self.first_source_index
    }

    #[getter]
    fn source_count(&self) -> u32 {
        self.source_count
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlParentSpan {
    destination_start: usize,
    destination_end: usize,
    source_start: usize,
    source_end: usize,
}

impl IlParentSpan {
    pub(crate) fn from_core(span: CoreIlParentSpan) -> Self {
        Self {
            destination_start: span.destination().start(),
            destination_end: span.destination().end(),
            source_start: span.source().start(),
            source_end: span.source().end(),
        }
    }
}

#[pymethods]
impl IlParentSpan {
    #[getter]
    fn destination_start(&self) -> usize {
        self.destination_start
    }

    #[getter]
    fn destination_end(&self) -> usize {
        self.destination_end
    }

    #[getter]
    fn source_start(&self) -> usize {
        self.source_start
    }

    #[getter]
    fn source_end(&self) -> usize {
        self.source_end
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlDominance {
    block: usize,
    immediate_dominator: Option<usize>,
    children: Vec<usize>,
    frontier: Vec<usize>,
    reachable: bool,
}

impl IlDominance {
    pub(crate) fn from_core(
        dominance: &CoreDominance,
        frontiers: &CoreDominanceFrontier,
        block: usize,
    ) -> Result<Self, CoreIlError> {
        let block_id = CoreIlBlockId::try_from_index(block)?;
        let immediate_dominator = dominance
            .immediate_dominator(block_id)
            .map(|dominator| dominator.index());
        let children = dominance
            .children_for(block_id)
            .iter()
            .map(|child| child.index())
            .collect();
        let frontier = frontiers
            .frontier_for(block_id)
            .iter()
            .map(|frontier| frontier.index())
            .collect();

        Ok(Self {
            block,
            immediate_dominator,
            children,
            frontier,
            reachable: dominance.is_reachable(block_id),
        })
    }
}

#[pymethods]
impl IlDominance {
    #[getter]
    fn block(&self) -> usize {
        self.block
    }

    #[getter]
    fn immediate_dominator(&self) -> Option<usize> {
        self.immediate_dominator
    }

    #[getter]
    fn children(&self) -> Vec<usize> {
        self.children.clone()
    }

    #[getter]
    fn frontier(&self) -> Vec<usize> {
        self.frontier.clone()
    }

    #[getter]
    fn reachable(&self) -> bool {
        self.reachable
    }
}
