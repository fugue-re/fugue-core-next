use std::path::PathBuf;
use std::sync::Arc;

use fugue_core::engine::AnalysisEngine;
use fugue_core::engine::change::ChangeRecord;
use fugue_core::il::common::{
    IlArtefact as CoreIlArtefact, IlArtefact, IlBlock as CoreIlBlock, IlBlockId as CoreIlBlockId,
    IlBlockProperties as CoreIlBlockProperties, IlDominance as CoreDominance,
    IlDominanceFrontier as CoreDominanceFrontier, IlError as CoreIlError, IlFormId as CoreIlFormId,
    IlGraph as CoreIlGraph, IlMetadata as CoreIlMetadata, IlParentSpan as CoreIlParentSpan,
    IlSourceSpan as CoreIlSourceSpan, IlValueId as CoreIlValueId, PersistableIl,
};
use fugue_core::il::ecode::ssa::{
    ECodeSsaBlockArg as CoreECodeSsaBlockArg, ECodeSsaIr as CoreECodeSsaIr,
    ECodeSsaLiveness as CoreECodeSsaLiveness, ECodeSsaMemoryDomain as CoreECodeSsaMemoryDomain,
    ECodeSsaOp as CoreECodeSsaOp, ECodeSsaUse as CoreECodeSsaUse, ECodeSsaUses as CoreECodeSsaUses,
    ECodeSsaValue as CoreECodeSsaValue, ECodeSsaValueKind as CoreECodeSsaValueKind,
};
use fugue_core::il::ecode::{
    ECodeExpr as CoreECodeExpr, ECodeIr as CoreECodeIr, ECodeStmt as CoreECodeStmt,
};
use fugue_core::il::pcode::{
    PCodeIr as CorePCodeIr, PCodeLocation as CorePCodeLocation, PCodeOp as CorePCodeOp,
    PCodeOpcode as CorePCodeOpcode,
};
use fugue_core::ir::{Address as CoreAddress, FunctionId as CoreFunctionId};
use fugue_core::project::Project as CoreProject;
use fugue_core::queries::QueryReader;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::address::Address;
use crate::binary::Binary;
use crate::errors::{BindingError, project_error};

#[pyclass(unsendable)]
pub(crate) struct Project {
    engine: AnalysisEngine,
    reader: QueryReader,
}

impl Project {
    fn parse_form(form: &str) -> PyResult<CoreIlFormId> {
        match form {
            "pcode" => Ok(<CorePCodeIr as IlArtefact>::FORM),
            "ecode" => Ok(<CoreECodeIr as IlArtefact>::FORM),
            "ecode_ssa" => Ok(<CoreECodeSsaIr as IlArtefact>::FORM),
            _ => CoreIlFormId::new(form).map_err(|_| BindingError::invalid_form(form).into()),
        }
    }

    fn from_core(inner: CoreProject) -> PyResult<Self> {
        let engine = AnalysisEngine::new(inner).map_err(project_error)?;
        let reader = engine.query_reader().map_err(project_error)?;
        Ok(Self { engine, reader })
    }
}

#[pymethods]
impl Project {
    #[staticmethod]
    fn from_binary(binary: &Binary) -> PyResult<Self> {
        let inner = CoreProject::new_transient(&binary.loader).map_err(project_error)?;
        Self::from_core(inner)
    }

    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = CoreProject::from_file_transient(path).map_err(project_error)?;
        Self::from_core(inner)
    }

    #[getter]
    fn revision(&self) -> PyResult<u64> {
        self.reader
            .revision()
            .map(|revision| revision.value())
            .map_err(project_error)
    }

    fn functions(&self) -> PyResult<Vec<Function>> {
        let project = self.reader.project().map_err(project_error)?;
        Ok(project
            .functions()
            .iter()
            .map(|function| Function::from_core(function.id(), function.entry()))
            .collect())
    }

    fn recover_functions(&mut self) -> PyResult<usize> {
        let before = self
            .reader
            .project()
            .map_err(project_error)?
            .functions()
            .len();
        self.engine.analyse().map_err(project_error)?;
        let after = self
            .reader
            .project()
            .map_err(project_error)?
            .functions()
            .len();
        Ok(after.saturating_sub(before))
    }

    fn pcode(&self, function: &Function) -> PyResult<Option<PCodeIr>> {
        self.reader
            .pcode(function.id)
            .map(|ir| ir.map(|ir| PCodeIr::from_core(Arc::unwrap_or_clone(ir))))
            .map_err(project_error)
    }

    fn ecode(&self, function: &Function) -> PyResult<Option<ECodeIr>> {
        self.reader
            .ecode(function.id)
            .map(|ir| ir.map(|ir| ECodeIr::from_core(Arc::unwrap_or_clone(ir))))
            .map_err(project_error)
    }

    fn ecode_ssa(&self, function: &Function) -> PyResult<Option<ECodeSsaIr>> {
        self.reader
            .ecode_ssa(function.id)
            .map(|ir| ir.map(|ir| ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))))
            .map_err(project_error)
    }

    fn has_lifted(&self, function: &Function, form: &str) -> PyResult<bool> {
        let form = Self::parse_form(form)?;
        let project = self.reader.project().map_err(project_error)?;
        if form == <CorePCodeIr as IlArtefact>::FORM {
            project.pcode(function.id).map(|ir| ir.is_some())
        } else if form == <CoreECodeIr as IlArtefact>::FORM {
            project.ecode(function.id).map(|ir| ir.is_some())
        } else if form == <CoreECodeSsaIr as IlArtefact>::FORM {
            project.ecode_ssa(function.id).map(|ir| ir.is_some())
        } else {
            Ok(false)
        }
        .map_err(project_error)
    }

    fn ensure_lifted(&mut self, function: &Function, form: &str) -> PyResult<bool> {
        let form = Self::parse_form(form)?;
        let changes = self
            .engine
            .ensure_lifted(function.id, form)
            .map_err(project_error)?;
        Ok(changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::LiftedMaterialised { .. })))
    }

    fn lifted_display(&self, function: &Function, form: &str) -> PyResult<Option<String>> {
        let form = Self::parse_form(form)?;
        if form == <CorePCodeIr as IlArtefact>::FORM {
            self.reader
                .pcode(function.id)
                .map(|ir| ir.map(|ir| ir.display().to_string()))
                .map_err(project_error)
        } else if form == <CoreECodeIr as IlArtefact>::FORM {
            self.reader
                .ecode(function.id)
                .map(|ir| ir.map(|ir| ir.display().to_string()))
                .map_err(project_error)
        } else if form == <CoreECodeSsaIr as IlArtefact>::FORM {
            self.reader
                .ecode_ssa(function.id)
                .map(|ir| ir.map(|ir| ir.display().to_string()))
                .map_err(project_error)
        } else {
            Ok(None)
        }
    }

    fn ecode_ssa_value_uses(
        &self,
        function: &Function,
    ) -> PyResult<Option<Vec<ECodeSsaValueUses>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .value_uses()
            .map(Some)
    }

    fn ecode_ssa_uses_for_value(
        &self,
        function: &Function,
        value: usize,
    ) -> PyResult<Option<Vec<ECodeSsaUse>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .uses_for_value(value)
            .map(Some)
    }

    fn ecode_ssa_liveness(&self, function: &Function) -> PyResult<Option<Vec<ECodeSsaLiveness>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .liveness()
            .map(Some)
    }

    fn ecode_ssa_live_in(&self, function: &Function, block: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .live_in(block)
            .map(Some)
    }

    fn ecode_ssa_live_out(
        &self,
        function: &Function,
        block: usize,
    ) -> PyResult<Option<Vec<usize>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .live_out(block)
            .map(Some)
    }

    fn ecode_ssa_dominance(&self, function: &Function) -> PyResult<Option<Vec<IlDominance>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .dominance()
            .map(Some)
    }

    fn ecode_ssa_dominance_frontier(
        &self,
        function: &Function,
        block: usize,
    ) -> PyResult<Option<Vec<usize>>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .dominance_frontier(block)
            .map(Some)
    }

    fn ecode_ssa_dominates(
        &self,
        function: &Function,
        dominator: usize,
        block: usize,
    ) -> PyResult<Option<bool>> {
        let Some(ir) = self.reader.ecode_ssa(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeSsaIr::from_core(Arc::unwrap_or_clone(ir))
            .dominates(dominator, block)
            .map(Some)
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Function {
    id: CoreFunctionId,
    entry: Address,
}

impl Function {
    fn from_core(id: CoreFunctionId, entry: CoreAddress) -> Self {
        Self {
            id,
            entry: Address::from_core(entry),
        }
    }
}

#[pymethods]
impl Function {
    #[getter]
    fn id(&self) -> String {
        let id = self.id;
        format!("{id:x}")
    }

    #[getter]
    fn entry(&self) -> Address {
        self.entry.clone()
    }

    fn __repr__(&self) -> String {
        let id = self.id();
        let entry = self.entry.display_text();
        format!("Function(id={id:?}, entry={entry})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IlMetadata {
    inner: CoreIlMetadata,
}

impl IlMetadata {
    fn from_core(metadata: CoreIlMetadata) -> Self {
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
    fn from_core(common: CoreIlGraph) -> Self {
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
        let predecessors = self.inner.predecessors();

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
pub(crate) struct PCodeIr {
    inner: CorePCodeIr,
}

impl PCodeIr {
    fn from_core(ir: CorePCodeIr) -> Self {
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

    fn operations(&self) -> PyResult<Vec<PCodeOperation>> {
        self.inner
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| PCodeOperation::from_core(&self.inner, index, operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn operations_for_source(&self, address: &Address) -> PyResult<Vec<PCodeOperation>> {
        self.inner
            .operations_for_source(address.inner())
            .map(|(index, operation)| {
                PCodeOperation::from_core(&self.inner, index.index(), operation)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
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
pub(crate) struct ECodeIr {
    inner: CoreECodeIr,
}

impl ECodeIr {
    fn from_core(ir: CoreECodeIr) -> Self {
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

    fn expressions(&self) -> PyResult<Vec<ECodeExpr>> {
        self.inner
            .expressions()
            .iter()
            .enumerate()
            .map(|(index, expression)| ECodeExpr::from_core(&self.inner, index, expression))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn statements(&self) -> PyResult<Vec<ECodeStmt>> {
        self.inner
            .statements()
            .iter()
            .enumerate()
            .map(|(index, statement)| ECodeStmt::from_core(&self.inner, index, statement))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn statements_for_source(&self, address: &Address) -> PyResult<Vec<ECodeStmt>> {
        self.inner
            .statements_for_source(address.inner())
            .map(|(index, statement)| ECodeStmt::from_core(&self.inner, index.index(), statement))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn __repr__(&self) -> String {
        let function = self.inner.metadata().function();
        format!("ECodeIr(function={function:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
pub(crate) struct ECodeSsaIr {
    inner: CoreECodeSsaIr,
}

impl ECodeSsaIr {
    fn from_core(ir: CoreECodeSsaIr) -> Self {
        Self { inner: ir }
    }
}

#[pymethods]
impl ECodeSsaIr {
    #[getter]
    fn form(&self) -> &'static str {
        <CoreECodeSsaIr as IlArtefact>::FORM_IDENTIFIER
    }

    #[getter]
    fn schema(&self) -> u16 {
        <CoreECodeSsaIr as PersistableIl>::SCHEMA.value()
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

    fn values(&self) -> Vec<ECodeSsaValue> {
        self.inner
            .values()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, value)| ECodeSsaValue::from_core(index, value))
            .collect()
    }

    fn value_uses(&self) -> PyResult<Vec<ECodeSsaValueUses>> {
        let uses = self.inner.analyse::<CoreECodeSsaUses>();
        self.inner
            .values()
            .iter()
            .enumerate()
            .map(|(value, _)| ECodeSsaValueUses::from_core(&uses, value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn uses_for_value(&self, value: usize) -> PyResult<Vec<ECodeSsaUse>> {
        let value = CoreIlValueId::try_from_index(value).map_err(project_error)?;
        let uses = self.inner.analyse::<CoreECodeSsaUses>();

        Ok(uses
            .uses_for(value)
            .iter()
            .copied()
            .map(ECodeSsaUse::from_core)
            .collect())
    }

    fn liveness(&self) -> PyResult<Vec<ECodeSsaLiveness>> {
        let liveness = self.inner.analyse::<CoreECodeSsaLiveness>();
        self.inner
            .graph()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| ECodeSsaLiveness::from_core(&liveness, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn live_in(&self, block: usize) -> PyResult<Vec<usize>> {
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let liveness = self.inner.analyse::<CoreECodeSsaLiveness>();

        Ok(liveness
            .live_in(block)
            .iter()
            .map(|value| value.index())
            .collect())
    }

    fn live_out(&self, block: usize) -> PyResult<Vec<usize>> {
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let liveness = self.inner.analyse::<CoreECodeSsaLiveness>();

        Ok(liveness
            .live_out(block)
            .iter()
            .map(|value| value.index())
            .collect())
    }

    fn dominance(&self) -> PyResult<Vec<IlDominance>> {
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

    fn dominance_frontier(&self, block: usize) -> PyResult<Vec<usize>> {
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let frontiers = self.inner.analyse::<CoreDominanceFrontier>();

        Ok(frontiers
            .frontier_for(block)
            .iter()
            .map(|frontier| frontier.index())
            .collect())
    }

    fn dominates(&self, dominator: usize, block: usize) -> PyResult<bool> {
        let dominator = CoreIlBlockId::try_from_index(dominator).map_err(project_error)?;
        let block = CoreIlBlockId::try_from_index(block).map_err(project_error)?;
        let dominance = self.inner.analyse::<CoreDominance>();

        Ok(dominance.dominates(dominator, block))
    }

    fn block_arguments(&self) -> Vec<ECodeSsaBlockArg> {
        self.inner
            .block_arguments()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, argument)| ECodeSsaBlockArg::from_core(index, argument))
            .collect()
    }

    fn edge_arguments(&self) -> PyResult<Vec<ECodeSsaEdgeArguments>> {
        self.inner
            .edge_arguments()
            .iter()
            .enumerate()
            .map(|(edge, _)| ECodeSsaEdgeArguments::from_core(&self.inner, edge))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn arguments_for_edge(&self, edge: usize) -> Vec<usize> {
        self.inner
            .arguments_for_edge(edge)
            .iter()
            .map(|argument| argument.index())
            .collect()
    }

    fn memory_domains(&self) -> Vec<ECodeSsaMemoryDomain> {
        self.inner
            .memory_domains()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, domain)| ECodeSsaMemoryDomain::from_core(index, domain))
            .collect()
    }

    fn operations(&self) -> PyResult<Vec<ECodeSsaOp>> {
        self.inner
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| ECodeSsaOp::from_core(&self.inner, index, operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn operations_for_source(&self, address: &Address) -> PyResult<Vec<ECodeSsaOp>> {
        self.inner
            .operations_for_source(address.inner())
            .map(|(index, operation)| ECodeSsaOp::from_core(&self.inner, index.index(), operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn __repr__(&self) -> String {
        let function = self.inner.metadata().function();
        format!("ECodeSsaIr(function={function:?})")
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
            operation_start: block.operations().start(),
            operation_end: block.operations().end(),
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
    first_pcode_index: u32,
    pcode_count: u32,
}

impl IlSourceSpan {
    fn from_core(span: CoreIlSourceSpan) -> Self {
        Self {
            address: Address::from_core(span.address()),
            destination_start: span.destination().start(),
            destination_end: span.destination().end(),
            first_pcode_index: span.first_pcode_index(),
            pcode_count: span.pcode_count(),
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
    fn first_pcode_index(&self) -> u32 {
        self.first_pcode_index
    }

    #[getter]
    fn pcode_count(&self) -> u32 {
        self.pcode_count
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
    fn from_core(span: CoreIlParentSpan) -> Self {
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
pub(crate) struct PCodeOperation {
    index: usize,
    opcode: &'static str,
    operands: Vec<usize>,
    output: Option<usize>,
    immediate: u32,
    address_space: Option<usize>,
    target: Option<Address>,
}

impl PCodeOperation {
    fn from_core(
        ir: &CorePCodeIr,
        index: usize,
        operation: &CorePCodeOp,
    ) -> Result<Self, CoreIlError> {
        let operands = ir
            .operation_operands_for(operation)
            .iter()
            .map(|operand| operand.index())
            .collect();
        let target = if matches!(
            operation.opcode(),
            CorePCodeOpcode::Branch | CorePCodeOpcode::CBranch | CorePCodeOpcode::Call
        ) {
            ir.target(operation.immediate())
                .map(|target| Address::from_core(target.address()))
        } else {
            None
        };

        Ok(Self {
            index,
            opcode: operation.opcode().mnemonic(),
            operands,
            output: operation.output().map(|output| output.index()),
            immediate: operation.immediate(),
            address_space: operation.address_space().map(|space| space.index()),
            target,
        })
    }
}

#[pymethods]
impl PCodeOperation {
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

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeExpr {
    index: usize,
    opcode: &'static str,
    operands: Vec<usize>,
    width: u32,
    immediate: u64,
    address_space: Option<usize>,
}

impl ECodeExpr {
    fn from_core(
        ir: &CoreECodeIr,
        index: usize,
        expression: &CoreECodeExpr,
    ) -> Result<Self, CoreIlError> {
        let operands = ir
            .expression_operands_for(expression)
            .iter()
            .map(|operand| operand.index())
            .collect();

        Ok(Self {
            index,
            opcode: expression.opcode().mnemonic(),
            operands,
            width: expression.width(),
            immediate: expression.immediate(),
            address_space: expression.address_space().map(|space| space.index()),
        })
    }
}

#[pymethods]
impl ECodeExpr {
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
    fn width(&self) -> u32 {
        self.width
    }

    #[getter]
    fn immediate(&self) -> u64 {
        self.immediate
    }

    #[getter]
    fn address_space(&self) -> Option<usize> {
        self.address_space
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeStmt {
    index: usize,
    opcode: &'static str,
    operands: Vec<usize>,
    value: Option<usize>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<usize>,
}

impl ECodeStmt {
    fn from_core(
        ir: &CoreECodeIr,
        index: usize,
        statement: &CoreECodeStmt,
    ) -> Result<Self, CoreIlError> {
        let operands = ir
            .statement_operands_for(statement)
            .iter()
            .map(|operand| operand.index())
            .collect();

        Ok(Self {
            index,
            opcode: statement.opcode().mnemonic(),
            operands,
            value: statement.value().map(|value| value.index()),
            immediate: statement.immediate(),
            address: statement.address().map(Address::from_core),
            address_space: statement.address_space().map(|space| space.index()),
        })
    }
}

#[pymethods]
impl ECodeStmt {
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
    fn value(&self) -> Option<usize> {
        self.value
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

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeSsaValue {
    index: usize,
    width: u32,
    definition_kind: &'static str,
    definition_index: u32,
}

impl ECodeSsaValue {
    fn from_core(index: usize, value: CoreECodeSsaValue) -> Self {
        let definition_kind = match value.definition_kind() {
            CoreECodeSsaValueKind::Operation => "operation",
            CoreECodeSsaValueKind::BlockArgument => "block_argument",
        };

        Self {
            index,
            width: value.width(),
            definition_kind,
            definition_index: value.definition_index(),
        }
    }
}

#[pymethods]
impl ECodeSsaValue {
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
    fn definition_index(&self) -> u32 {
        self.definition_index
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeSsaValueUses {
    value: usize,
    uses: Vec<ECodeSsaUse>,
}

impl ECodeSsaValueUses {
    fn from_core(uses: &CoreECodeSsaUses, value: usize) -> Result<Self, CoreIlError> {
        let value_id = CoreIlValueId::try_from_index(value)?;
        let uses = uses
            .uses_for(value_id)
            .iter()
            .copied()
            .map(ECodeSsaUse::from_core)
            .collect();

        Ok(Self { value, uses })
    }
}

#[pymethods]
impl ECodeSsaValueUses {
    #[getter]
    fn value(&self) -> usize {
        self.value
    }

    #[getter]
    fn uses(&self) -> Vec<ECodeSsaUse> {
        self.uses.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeSsaUse {
    user: usize,
    operand_index: u32,
}

impl ECodeSsaUse {
    fn from_core(use_record: CoreECodeSsaUse) -> Self {
        Self {
            user: use_record.user().index(),
            operand_index: use_record.operand_index(),
        }
    }
}

#[pymethods]
impl ECodeSsaUse {
    #[getter]
    fn user(&self) -> usize {
        self.user
    }

    #[getter]
    fn operand_index(&self) -> u32 {
        self.operand_index
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeSsaLiveness {
    block: usize,
    live_in: Vec<usize>,
    live_out: Vec<usize>,
}

impl ECodeSsaLiveness {
    fn from_core(liveness: &CoreECodeSsaLiveness, block: usize) -> Result<Self, CoreIlError> {
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
impl ECodeSsaLiveness {
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
pub(crate) struct IlDominance {
    block: usize,
    immediate_dominator: Option<usize>,
    children: Vec<usize>,
    frontier: Vec<usize>,
    reachable: bool,
}

impl IlDominance {
    fn from_core(
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

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeSsaBlockArg {
    index: usize,
    block: usize,
    value: usize,
    width: u32,
}

impl ECodeSsaBlockArg {
    fn from_core(index: usize, argument: CoreECodeSsaBlockArg) -> Self {
        Self {
            index,
            block: argument.block().index(),
            value: argument.value().index(),
            width: argument.width(),
        }
    }
}

#[pymethods]
impl ECodeSsaBlockArg {
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
pub(crate) struct ECodeSsaEdgeArguments {
    edge: usize,
    arguments: Vec<usize>,
}

impl ECodeSsaEdgeArguments {
    fn from_core(ir: &CoreECodeSsaIr, edge: usize) -> Result<Self, CoreIlError> {
        let arguments = ir
            .arguments_for_edge(edge)
            .iter()
            .map(|argument| argument.index())
            .collect();

        Ok(Self { edge, arguments })
    }
}

#[pymethods]
impl ECodeSsaEdgeArguments {
    #[getter]
    fn edge(&self) -> usize {
        self.edge
    }

    #[getter]
    fn arguments(&self) -> Vec<usize> {
        self.arguments.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct ECodeSsaMemoryDomain {
    index: usize,
    address_space: usize,
}

impl ECodeSsaMemoryDomain {
    fn from_core(index: usize, domain: CoreECodeSsaMemoryDomain) -> Self {
        Self {
            index,
            address_space: domain.space().index(),
        }
    }
}

#[pymethods]
impl ECodeSsaMemoryDomain {
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
pub(crate) struct ECodeSsaOp {
    index: usize,
    opcode: &'static str,
    results: Vec<usize>,
    operands: Vec<usize>,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<usize>,
}

impl ECodeSsaOp {
    fn from_core(
        ir: &CoreECodeSsaIr,
        index: usize,
        operation: &CoreECodeSsaOp,
    ) -> Result<Self, CoreIlError> {
        let results = operation.results().start()..operation.results().end();
        let results = results.collect();
        let operands = ir
            .operation_operands_for(operation)
            .iter()
            .map(|operand| operand.index())
            .collect();

        Ok(Self {
            index,
            opcode: operation.opcode().mnemonic(),
            results,
            operands,
            width: operation.width(),
            immediate: operation.immediate(),
            address: operation.address().map(Address::from_core),
            address_space: operation.address_space().map(|space| space.index()),
        })
    }
}

#[pymethods]
impl ECodeSsaOp {
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

pub(crate) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Project>()?;
    module.add_class::<Function>()?;
    module.add_class::<IlMetadata>()?;
    module.add_class::<IlGraph>()?;
    module.add_class::<PCodeIr>()?;
    module.add_class::<ECodeIr>()?;
    module.add_class::<ECodeSsaIr>()?;
    module.add_class::<IlBlock>()?;
    module.add_class::<IlBlockPredecessors>()?;
    module.add_class::<IlSourceSpan>()?;
    module.add_class::<IlParentSpan>()?;
    module.add_class::<PCodeLocation>()?;
    module.add_class::<PCodeOperation>()?;
    module.add_class::<ECodeExpr>()?;
    module.add_class::<ECodeStmt>()?;
    module.add_class::<ECodeSsaValue>()?;
    module.add_class::<ECodeSsaValueUses>()?;
    module.add_class::<ECodeSsaUse>()?;
    module.add_class::<ECodeSsaLiveness>()?;
    module.add_class::<IlDominance>()?;
    module.add_class::<ECodeSsaBlockArg>()?;
    module.add_class::<ECodeSsaEdgeArguments>()?;
    module.add_class::<ECodeSsaMemoryDomain>()?;
    module.add_class::<ECodeSsaOp>()?;

    Ok(())
}
