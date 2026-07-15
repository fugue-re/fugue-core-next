use std::path::PathBuf;

use fugue_core::analysis::AnalysisPass;
use fugue_core::analysis::function::recovery::FunctionRecovery;
use fugue_core::il::common::{
    ArtefactDigest as CoreArtefactDigest, Block as CoreBlock, BlockId as CoreBlockId, BuildStatus,
    IlError as CoreIlError, IrArtefact as CoreIrArtefact, IrLevel as CoreIrLevel,
    MappingRun as CoreMappingRun, RawIrArtefact, SourceRun as CoreSourceRun,
    ValueId as CoreValueId,
};
use fugue_core::il::llil::ssa::{
    BlockArgument as CoreSsaBlockArgument, Dominance as CoreDominance,
    DominanceFrontier as CoreDominanceFrontier, Liveness as CoreLiveness,
    MemoryDomain as CoreSsaMemoryDomain, SsaBody as CoreSsaBody, SsaOperation as CoreSsaOperation,
    Use as CoreSsaUse, UseIndex as CoreUseIndex, Value as CoreSsaValue,
    ValueDefinitionKind as CoreValueDefinitionKind,
};
use fugue_core::il::llil::{
    Expression as CoreLlilExpression, LlilBody as CoreLlilBody, Statement as CoreLlilStatement,
};
use fugue_core::il::pcode::{
    Location as CorePCodeLocation, Opcode as CorePCodeOpcode, Operation as CorePCodeOperation,
    PCodeBody as CorePCodeBody,
};
use fugue_core::ir::{Address as CoreAddress, FunctionId as CoreFunctionId};
use fugue_core::project::Project as CoreProject;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::address::Address;
use crate::binary::Binary;
use crate::errors::{BindingError, project_error};

#[pyclass(unsendable)]
pub(crate) struct Project {
    inner: CoreProject,
}

impl Project {
    fn ir_level(level: &str) -> PyResult<CoreIrLevel> {
        CoreIrLevel::from_name(level).ok_or_else(|| BindingError::invalid_ir_level(level).into())
    }
}

#[pymethods]
impl Project {
    #[staticmethod]
    fn from_binary(binary: &Binary) -> PyResult<Self> {
        let inner = CoreProject::new_transient(&binary.loader).map_err(project_error)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = CoreProject::from_file_transient(path).map_err(project_error)?;
        Ok(Self { inner })
    }

    #[getter]
    fn revision(&self) -> u64 {
        self.inner.revision().value()
    }

    fn functions(&self) -> Vec<Function> {
        self.inner
            .functions()
            .iter()
            .map(|function| Function::from_core(function.id(), function.entry()))
            .collect()
    }

    fn recover_functions(&mut self) -> PyResult<usize> {
        let before = self.inner.functions().len();
        let mut recovery = FunctionRecovery::new();

        recovery.analyse(&mut self.inner).map_err(project_error)?;

        Ok(self.inner.functions().len().saturating_sub(before))
    }

    fn ir_artefact(&self, function: &Function, level: &str) -> PyResult<Option<IrArtefact>> {
        let level = Self::ir_level(level)?;
        self.inner
            .ir_artefact(function.id, level)
            .map(|artefact| artefact.map(IrArtefact::from_core))
            .map_err(project_error)
    }

    fn ir_artefacts(&self, function: &Function) -> PyResult<Vec<IrArtefact>> {
        let mut artefacts = Vec::new();

        for level in CoreIrLevel::ALL {
            if let Some(artefact) = self
                .inner
                .ir_artefact(function.id, level)
                .map_err(project_error)?
            {
                artefacts.push(IrArtefact::from_core(artefact));
            }
        }

        Ok(artefacts)
    }

    fn has_ir(&self, function: &Function, level: &str) -> PyResult<bool> {
        Ok(self.ir_artefact(function, level)?.is_some())
    }

    fn ensure_ir(&mut self, function: &Function, level: &str) -> PyResult<bool> {
        let level = Self::ir_level(level)?;
        let status = BuildStatus::new();
        let mut transaction = self.inner.transaction("python");

        match transaction.ensure_ir(function.id, level, &status) {
            Ok(published) => {
                transaction.commit().map_err(project_error)?;
                Ok(published)
            }
            Err(error) => {
                if let Err(rollback) = transaction.rollback() {
                    return Err(project_error(rollback));
                }
                Err(project_error(error))
            }
        }
    }

    fn ir_text(&self, function: &Function, level: &str) -> PyResult<Option<String>> {
        let level = Self::ir_level(level)?;
        match level {
            CoreIrLevel::PCode => self
                .inner
                .pcode_body(function.id)
                .map(|body| body.map(|body| body.display().to_string()))
                .map_err(project_error),
            CoreIrLevel::Llil => self
                .inner
                .llil_body(function.id)
                .map(|body| body.map(|body| body.display().to_string()))
                .map_err(project_error),
            CoreIrLevel::LlilSsa => self
                .inner
                .llil_ssa_body(function.id)
                .map(|body| body.map(|body| body.display().to_string()))
                .map_err(project_error),
            CoreIrLevel::MappedMlil | CoreIrLevel::Mlil => Err(project_error(
                CoreIlError::mlil_build_scheduling_unsupported(),
            )),
        }
    }

    fn llil_ssa_value_uses(&self, function: &Function) -> PyResult<Option<Vec<LlilSsaValueUses>>> {
        let Some(body) = self
            .inner
            .llil_ssa_body(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let Some(use_index) = self
            .inner
            .llil_ssa_use_index(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };

        let uses = body
            .values()
            .iter()
            .enumerate()
            .map(|(value, _)| LlilSsaValueUses::from_core(&use_index, value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(uses))
    }

    fn llil_ssa_uses_for_value(
        &self,
        function: &Function,
        value: usize,
    ) -> PyResult<Option<Vec<LlilSsaUse>>> {
        let value = CoreValueId::try_from_index(value).map_err(project_error)?;
        let Some(use_index) = self
            .inner
            .llil_ssa_use_index(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let uses = use_index
            .uses_for(value)
            .iter()
            .copied()
            .map(LlilSsaUse::from_core)
            .collect();

        Ok(Some(uses))
    }

    fn llil_ssa_liveness(&self, function: &Function) -> PyResult<Option<Vec<LlilSsaLiveness>>> {
        let Some(body) = self
            .inner
            .llil_ssa_body(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let Some(liveness) = self
            .inner
            .llil_ssa_liveness(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let live = body
            .common()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| LlilSsaLiveness::from_core(&liveness, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(live))
    }

    fn llil_ssa_live_in(&self, function: &Function, block: usize) -> PyResult<Option<Vec<usize>>> {
        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let Some(liveness) = self
            .inner
            .llil_ssa_liveness(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let values = liveness
            .live_in(block)
            .iter()
            .map(|value| value.index())
            .collect();

        Ok(Some(values))
    }

    fn llil_ssa_live_out(&self, function: &Function, block: usize) -> PyResult<Option<Vec<usize>>> {
        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let Some(liveness) = self
            .inner
            .llil_ssa_liveness(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let values = liveness
            .live_out(block)
            .iter()
            .map(|value| value.index())
            .collect();

        Ok(Some(values))
    }

    fn llil_ssa_dominance(&self, function: &Function) -> PyResult<Option<Vec<LlilSsaDominance>>> {
        let Some(body) = self
            .inner
            .llil_ssa_body(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let Some(dominance) = self
            .inner
            .llil_ssa_dominance(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let frontiers = dominance
            .frontiers(body.common().blocks(), body.common().successors())
            .map_err(project_error)?;
        let rows = body
            .common()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| LlilSsaDominance::from_core(&dominance, &frontiers, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(rows))
    }

    fn llil_ssa_dominance_frontier(
        &self,
        function: &Function,
        block: usize,
    ) -> PyResult<Option<Vec<usize>>> {
        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let Some(frontiers) = self
            .inner
            .llil_ssa_dominance_frontiers(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };
        let values = frontiers
            .frontier(block)
            .iter()
            .map(|frontier| frontier.index())
            .collect();

        Ok(Some(values))
    }

    fn llil_ssa_dominates(
        &self,
        function: &Function,
        dominator: usize,
        block: usize,
    ) -> PyResult<Option<bool>> {
        let dominator = CoreBlockId::try_from_index(dominator).map_err(project_error)?;
        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let Some(dominance) = self
            .inner
            .llil_ssa_dominance(function.id)
            .map_err(project_error)?
        else {
            return Ok(None);
        };

        Ok(Some(dominance.dominates(dominator, block)))
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
pub(crate) struct ArtefactDigest {
    bytes: [u8; 32],
}

impl ArtefactDigest {
    fn from_core(digest: CoreArtefactDigest) -> Self {
        Self {
            bytes: *digest.bytes(),
        }
    }

    fn hex_text(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut text = String::with_capacity(64);
        for byte in self.bytes {
            text.push(HEX[(byte >> 4) as usize] as char);
            text.push(HEX[(byte & 0x0f) as usize] as char);
        }

        text
    }
}

#[pymethods]
impl ArtefactDigest {
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.bytes).unbind()
    }

    #[getter]
    fn hex(&self) -> String {
        self.hex_text()
    }

    fn __repr__(&self) -> String {
        let hex = self.hex_text();
        format!("ArtefactDigest({hex:?})")
    }
}

#[pyclass(frozen, skip_from_py_object)]
pub(crate) struct IrArtefact {
    inner: RawIrArtefact,
}

impl IrArtefact {
    fn from_core(artefact: RawIrArtefact) -> Self {
        Self { inner: artefact }
    }
}

#[pymethods]
impl IrArtefact {
    #[getter]
    fn level(&self) -> &str {
        self.inner.header().level().name()
    }

    #[getter]
    fn function(&self) -> String {
        let function = self.inner.header().function();
        format!("{function:x}")
    }

    #[getter]
    fn schema(&self) -> u16 {
        self.inner.header().schema().value()
    }

    #[getter]
    fn dialect(&self) -> u16 {
        self.inner.header().dialect().value()
    }

    #[getter]
    fn input_revision(&self) -> u64 {
        self.inner.header().input_revision()
    }

    #[getter]
    fn parent_digest(&self) -> ArtefactDigest {
        ArtefactDigest::from_core(self.inner.header().parent_digest())
    }

    #[getter]
    fn address_topology_digest(&self) -> ArtefactDigest {
        ArtefactDigest::from_core(self.inner.header().address_topology_digest())
    }

    #[getter]
    fn transform_digest(&self) -> ArtefactDigest {
        ArtefactDigest::from_core(self.inner.header().transform_digest())
    }

    #[getter]
    fn content_digest(&self) -> ArtefactDigest {
        ArtefactDigest::from_core(self.inner.header().content_digest())
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, self.inner.payload()).unbind()
    }

    fn blocks(&self) -> PyResult<Vec<IrBlock>> {
        let successors = self.inner.body().successors();
        self.inner
            .body()
            .blocks()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, block)| IrBlock::from_core(index, block, successors))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)
    }

    fn block_predecessors(&self) -> PyResult<Vec<IrBlockPredecessors>> {
        let predecessors = self.inner.body().predecessors().map_err(project_error)?;

        self.inner
            .body()
            .blocks()
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let block = CoreBlockId::try_from_index(index)?;
                Ok(IrBlockPredecessors::from_core(
                    index,
                    predecessors.predecessors(block),
                ))
            })
            .collect::<Result<Vec<_>, CoreIlError>>()
            .map_err(project_error)
    }

    fn source_runs(&self) -> Vec<IrSourceRun> {
        self.inner
            .body()
            .source_runs()
            .iter()
            .copied()
            .map(IrSourceRun::from_core)
            .collect()
    }

    fn mapping_runs(&self) -> Vec<IrMappingRun> {
        self.inner
            .body()
            .mapping_runs()
            .iter()
            .copied()
            .map(IrMappingRun::from_core)
            .collect()
    }

    fn source_for_destination(&self, node: u32) -> Option<IrSourceRun> {
        self.inner
            .body()
            .source_for_destination(node)
            .map(IrSourceRun::from_core)
    }

    fn destinations_for_source(
        &self,
        machine_address: &Address,
        pcode_index: u32,
    ) -> Vec<IrSourceRun> {
        self.inner
            .body()
            .destinations_for_source(machine_address.inner(), pcode_index)
            .map(IrSourceRun::from_core)
            .collect()
    }

    fn mapping_for_destination(&self, node: u32) -> Option<IrMappingRun> {
        self.inner
            .body()
            .mapping_for_destination(node)
            .map(IrMappingRun::from_core)
    }

    fn mappings_for_source(&self, node: u32) -> Vec<IrMappingRun> {
        self.inner
            .body()
            .mappings_for_source(node)
            .map(IrMappingRun::from_core)
            .collect()
    }

    fn pcode_locations(&self) -> PyResult<Option<Vec<PCodeLocation>>> {
        let Some(body) = self.pcode_body()? else {
            return Ok(None);
        };

        Ok(Some(
            body.locations()
                .iter()
                .copied()
                .enumerate()
                .map(|(index, location)| PCodeLocation::from_core(index, location))
                .collect(),
        ))
    }

    fn pcode_operations(&self) -> PyResult<Option<Vec<PCodeOperation>>> {
        let Some(body) = self.pcode_body()? else {
            return Ok(None);
        };

        let operations = body
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| PCodeOperation::from_core(&body, index, operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(operations))
    }

    fn pcode_operations_for_source(
        &self,
        machine_address: &Address,
    ) -> PyResult<Option<Vec<PCodeOperation>>> {
        let Some(body) = self.pcode_body()? else {
            return Ok(None);
        };

        let operations = body
            .operations_for_source(machine_address.inner())
            .map(|(index, operation)| PCodeOperation::from_core(&body, index, operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(operations))
    }

    fn pcode_text_for_source(&self, machine_address: &Address) -> PyResult<Option<String>> {
        let Some(body) = self.pcode_body()? else {
            return Ok(None);
        };

        Ok(Some(
            body.display_source(machine_address.inner()).to_string(),
        ))
    }

    fn llil_expressions(&self) -> PyResult<Option<Vec<LlilExpression>>> {
        let Some(body) = self.llil_body()? else {
            return Ok(None);
        };

        let expressions = body
            .expressions()
            .iter()
            .enumerate()
            .map(|(index, expression)| LlilExpression::from_core(&body, index, expression))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(expressions))
    }

    fn llil_statements(&self) -> PyResult<Option<Vec<LlilStatement>>> {
        let Some(body) = self.llil_body()? else {
            return Ok(None);
        };

        let statements = body
            .statements()
            .iter()
            .enumerate()
            .map(|(index, statement)| LlilStatement::from_core(&body, index, statement))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(statements))
    }

    fn llil_statements_for_source(
        &self,
        machine_address: &Address,
    ) -> PyResult<Option<Vec<LlilStatement>>> {
        let Some(body) = self.llil_body()? else {
            return Ok(None);
        };

        let statements = body
            .statements_for_source(machine_address.inner())
            .map(|(index, statement)| LlilStatement::from_core(&body, index, statement))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(statements))
    }

    fn llil_ssa_values(&self) -> PyResult<Option<Vec<LlilSsaValue>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        Ok(Some(
            body.values()
                .iter()
                .copied()
                .enumerate()
                .map(|(index, value)| LlilSsaValue::from_core(index, value))
                .collect(),
        ))
    }

    fn llil_ssa_value_uses(&self) -> PyResult<Option<Vec<LlilSsaValueUses>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let use_index = body.use_index().map_err(project_error)?;
        let uses = body
            .values()
            .iter()
            .enumerate()
            .map(|(value, _)| LlilSsaValueUses::from_core(&use_index, value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(uses))
    }

    fn llil_ssa_uses_for_value(&self, value: usize) -> PyResult<Option<Vec<LlilSsaUse>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let value = CoreValueId::try_from_index(value).map_err(project_error)?;
        let use_index = body.use_index().map_err(project_error)?;
        let uses = use_index
            .uses_for(value)
            .iter()
            .copied()
            .map(LlilSsaUse::from_core)
            .collect();

        Ok(Some(uses))
    }

    fn llil_ssa_liveness(&self) -> PyResult<Option<Vec<LlilSsaLiveness>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let liveness = body.liveness().map_err(project_error)?;
        let live = body
            .common()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| LlilSsaLiveness::from_core(&liveness, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(live))
    }

    fn llil_ssa_live_in(&self, block: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let liveness = body.liveness().map_err(project_error)?;
        let values = liveness
            .live_in(block)
            .iter()
            .map(|value| value.index())
            .collect();

        Ok(Some(values))
    }

    fn llil_ssa_live_out(&self, block: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let liveness = body.liveness().map_err(project_error)?;
        let values = liveness
            .live_out(block)
            .iter()
            .map(|value| value.index())
            .collect();

        Ok(Some(values))
    }

    fn llil_ssa_dominance(&self) -> PyResult<Option<Vec<LlilSsaDominance>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let dominance = body.dominance().map_err(project_error)?;
        let frontiers = dominance
            .frontiers(body.common().blocks(), body.common().successors())
            .map_err(project_error)?;
        let rows = body
            .common()
            .blocks()
            .iter()
            .enumerate()
            .map(|(block, _)| LlilSsaDominance::from_core(&dominance, &frontiers, block))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(rows))
    }

    fn llil_ssa_dominance_frontier(&self, block: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let frontiers = body.dominance_frontiers().map_err(project_error)?;
        let values = frontiers
            .frontier(block)
            .iter()
            .map(|frontier| frontier.index())
            .collect();

        Ok(Some(values))
    }

    fn llil_ssa_dominates(&self, dominator: usize, block: usize) -> PyResult<Option<bool>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let dominator = CoreBlockId::try_from_index(dominator).map_err(project_error)?;
        let block = CoreBlockId::try_from_index(block).map_err(project_error)?;
        let dominance = body.dominance().map_err(project_error)?;

        Ok(Some(dominance.dominates(dominator, block)))
    }

    fn llil_ssa_block_arguments(&self) -> PyResult<Option<Vec<LlilSsaBlockArgument>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        Ok(Some(
            body.block_arguments()
                .iter()
                .copied()
                .enumerate()
                .map(|(index, argument)| LlilSsaBlockArgument::from_core(index, argument))
                .collect(),
        ))
    }

    fn llil_ssa_edge_arguments(&self) -> PyResult<Option<Vec<LlilSsaEdgeArguments>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let arguments = body
            .edge_arguments()
            .iter()
            .enumerate()
            .map(|(edge, _)| LlilSsaEdgeArguments::from_core(&body, edge))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(arguments))
    }

    fn llil_ssa_arguments_for_edge(&self, edge: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let arguments = body
            .arguments_for_edge(edge)
            .map(|arguments| {
                arguments
                    .iter()
                    .map(|argument| argument.index())
                    .collect::<Vec<_>>()
            })
            .map_err(project_error)?;

        Ok(Some(arguments))
    }

    fn llil_ssa_memory_domains(&self) -> PyResult<Option<Vec<LlilSsaMemoryDomain>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        Ok(Some(
            body.memory_domains()
                .iter()
                .copied()
                .enumerate()
                .map(|(index, domain)| LlilSsaMemoryDomain::from_core(index, domain))
                .collect(),
        ))
    }

    fn llil_ssa_operations(&self) -> PyResult<Option<Vec<LlilSsaOperation>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let operations = body
            .operations()
            .iter()
            .enumerate()
            .map(|(index, operation)| LlilSsaOperation::from_core(&body, index, operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(operations))
    }

    fn llil_ssa_operations_for_source(
        &self,
        machine_address: &Address,
    ) -> PyResult<Option<Vec<LlilSsaOperation>>> {
        let Some(body) = self.llil_ssa_body()? else {
            return Ok(None);
        };

        let operations = body
            .operations_for_source(machine_address.inner())
            .map(|(index, operation)| LlilSsaOperation::from_core(&body, index, operation))
            .collect::<Result<Vec<_>, _>>()
            .map_err(project_error)?;

        Ok(Some(operations))
    }

    fn __repr__(&self) -> String {
        let level = self.level();
        let function = self.function();
        format!("IrArtefact(level={level:?}, function={function:?})")
    }
}

impl IrArtefact {
    fn pcode_body(&self) -> PyResult<Option<CorePCodeBody>> {
        if self.inner.header().level() != CoreIrLevel::PCode {
            return Ok(None);
        }

        CorePCodeBody::from_raw_artefact(self.inner.clone())
            .map(Some)
            .map_err(project_error)
    }

    fn llil_body(&self) -> PyResult<Option<CoreLlilBody>> {
        if self.inner.header().level() != CoreIrLevel::Llil {
            return Ok(None);
        }

        CoreLlilBody::from_raw_artefact(self.inner.clone())
            .map(Some)
            .map_err(project_error)
    }

    fn llil_ssa_body(&self) -> PyResult<Option<CoreSsaBody>> {
        if self.inner.header().level() != CoreIrLevel::LlilSsa {
            return Ok(None);
        }

        CoreSsaBody::from_raw_artefact(self.inner.clone())
            .map(Some)
            .map_err(project_error)
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IrBlock {
    index: usize,
    operation_start: usize,
    operation_end: usize,
    successor_start: usize,
    successor_end: usize,
    successors: Vec<usize>,
    flags: u16,
}

impl IrBlock {
    fn from_core(
        index: usize,
        block: CoreBlock,
        successors: &[CoreBlockId],
    ) -> Result<Self, CoreIlError> {
        let successors = block
            .successors()
            .checked_slice(successors)?
            .iter()
            .map(|successor| successor.index())
            .collect();

        Ok(Self {
            index,
            operation_start: block.operations().start(),
            operation_end: block.operations().end(),
            successor_start: block.successors().start(),
            successor_end: block.successors().end(),
            successors,
            flags: block.flags(),
        })
    }
}

#[pymethods]
impl IrBlock {
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
    fn flags(&self) -> u16 {
        self.flags
    }

    #[getter]
    fn entry(&self) -> bool {
        self.flags & CoreBlock::ENTRY != 0
    }

    #[getter]
    fn exit(&self) -> bool {
        self.flags & CoreBlock::EXIT != 0
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IrBlockPredecessors {
    block: usize,
    predecessors: Vec<usize>,
}

impl IrBlockPredecessors {
    fn from_core(block: usize, predecessors: &[CoreBlockId]) -> Self {
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
impl IrBlockPredecessors {
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
pub(crate) struct IrSourceRun {
    machine_address: Address,
    destination_start: usize,
    destination_end: usize,
    pcode_start: u32,
    pcode_count: u32,
}

impl IrSourceRun {
    fn from_core(run: CoreSourceRun) -> Self {
        Self {
            machine_address: Address::from_core(run.machine_address()),
            destination_start: run.destination().start(),
            destination_end: run.destination().end(),
            pcode_start: run.first_pcode_index(),
            pcode_count: run.pcode_count(),
        }
    }
}

#[pymethods]
impl IrSourceRun {
    #[getter]
    fn machine_address(&self) -> Address {
        self.machine_address.clone()
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
    fn pcode_start(&self) -> u32 {
        self.pcode_start
    }

    #[getter]
    fn pcode_count(&self) -> u32 {
        self.pcode_count
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct IrMappingRun {
    destination_start: usize,
    destination_end: usize,
    source_start: usize,
    source_end: usize,
}

impl IrMappingRun {
    fn from_core(run: CoreMappingRun) -> Self {
        Self {
            destination_start: run.destination().start(),
            destination_end: run.destination().end(),
            source_start: run.source().start(),
            source_end: run.source().end(),
        }
    }
}

#[pymethods]
impl IrMappingRun {
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
    width: u16,
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
            width: location.width(),
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
    fn width(&self) -> u16 {
        self.width
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
    effect_space: Option<usize>,
    target: Option<Address>,
}

impl PCodeOperation {
    fn from_core(
        body: &CorePCodeBody,
        index: usize,
        operation: &CorePCodeOperation,
    ) -> Result<Self, CoreIlError> {
        let operands = body
            .operation_operands(operation)?
            .iter()
            .map(|operand| operand.index())
            .collect();
        let target = if matches!(
            operation.opcode(),
            CorePCodeOpcode::Branch | CorePCodeOpcode::CBranch | CorePCodeOpcode::Call
        ) {
            body.target(operation.immediate()).map(Address::from_core)
        } else {
            None
        };

        Ok(Self {
            index,
            opcode: operation.opcode().mnemonic(),
            operands,
            output: operation.output().map(|output| output.index()),
            immediate: operation.immediate(),
            effect_space: operation.effect_space().map(|space| space.index()),
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
    fn effect_space(&self) -> Option<usize> {
        self.effect_space
    }

    #[getter]
    fn target(&self) -> Option<Address> {
        self.target.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct LlilExpression {
    index: usize,
    opcode: &'static str,
    operands: Vec<usize>,
    width: u32,
    immediate: u64,
    address_space: Option<usize>,
}

impl LlilExpression {
    fn from_core(
        body: &CoreLlilBody,
        index: usize,
        expression: &CoreLlilExpression,
    ) -> Result<Self, CoreIlError> {
        let operands = body
            .expression_operands_for(expression)?
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
impl LlilExpression {
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
pub(crate) struct LlilStatement {
    index: usize,
    opcode: &'static str,
    operands: Vec<usize>,
    value: Option<usize>,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<usize>,
}

impl LlilStatement {
    fn from_core(
        body: &CoreLlilBody,
        index: usize,
        statement: &CoreLlilStatement,
    ) -> Result<Self, CoreIlError> {
        let operands = body
            .statement_operands_for(statement)?
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
impl LlilStatement {
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
pub(crate) struct LlilSsaValue {
    index: usize,
    width: u32,
    definition_kind: &'static str,
    definition_index: u32,
}

impl LlilSsaValue {
    fn from_core(index: usize, value: CoreSsaValue) -> Self {
        let definition_kind = match value.definition_kind() {
            CoreValueDefinitionKind::Operation => "operation",
            CoreValueDefinitionKind::BlockArgument => "block_argument",
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
impl LlilSsaValue {
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
pub(crate) struct LlilSsaValueUses {
    value: usize,
    uses: Vec<LlilSsaUse>,
}

impl LlilSsaValueUses {
    fn from_core(use_index: &CoreUseIndex, value: usize) -> Result<Self, CoreIlError> {
        let value_id = CoreValueId::try_from_index(value)?;
        let uses = use_index
            .uses_for(value_id)
            .iter()
            .copied()
            .map(LlilSsaUse::from_core)
            .collect();

        Ok(Self { value, uses })
    }
}

#[pymethods]
impl LlilSsaValueUses {
    #[getter]
    fn value(&self) -> usize {
        self.value
    }

    #[getter]
    fn uses(&self) -> Vec<LlilSsaUse> {
        self.uses.clone()
    }
}

#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct LlilSsaUse {
    user: usize,
    operand_index: u32,
}

impl LlilSsaUse {
    fn from_core(use_record: CoreSsaUse) -> Self {
        Self {
            user: use_record.user().index(),
            operand_index: use_record.operand_index(),
        }
    }
}

#[pymethods]
impl LlilSsaUse {
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
pub(crate) struct LlilSsaLiveness {
    block: usize,
    live_in: Vec<usize>,
    live_out: Vec<usize>,
}

impl LlilSsaLiveness {
    fn from_core(liveness: &CoreLiveness, block: usize) -> Result<Self, CoreIlError> {
        let block_id = CoreBlockId::try_from_index(block)?;
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
impl LlilSsaLiveness {
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
pub(crate) struct LlilSsaDominance {
    block: usize,
    immediate_dominator: Option<usize>,
    children: Vec<usize>,
    frontier: Vec<usize>,
    reachable: bool,
}

impl LlilSsaDominance {
    fn from_core(
        dominance: &CoreDominance,
        frontiers: &CoreDominanceFrontier,
        block: usize,
    ) -> Result<Self, CoreIlError> {
        let block_id = CoreBlockId::try_from_index(block)?;
        let immediate_dominator = dominance
            .immediate_dominator(block_id)
            .map(|dominator| dominator.index());
        let children = dominance
            .children(block_id)
            .iter()
            .map(|child| child.index())
            .collect();
        let frontier = frontiers
            .frontier(block_id)
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
impl LlilSsaDominance {
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
pub(crate) struct LlilSsaBlockArgument {
    index: usize,
    block: usize,
    value: usize,
    width: u32,
}

impl LlilSsaBlockArgument {
    fn from_core(index: usize, argument: CoreSsaBlockArgument) -> Self {
        Self {
            index,
            block: argument.block().index(),
            value: argument.value().index(),
            width: argument.width(),
        }
    }
}

#[pymethods]
impl LlilSsaBlockArgument {
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
pub(crate) struct LlilSsaEdgeArguments {
    edge: usize,
    arguments: Vec<usize>,
}

impl LlilSsaEdgeArguments {
    fn from_core(body: &CoreSsaBody, edge: usize) -> Result<Self, CoreIlError> {
        let arguments = body
            .arguments_for_edge(edge)?
            .iter()
            .map(|argument| argument.index())
            .collect();

        Ok(Self { edge, arguments })
    }
}

#[pymethods]
impl LlilSsaEdgeArguments {
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
pub(crate) struct LlilSsaMemoryDomain {
    index: usize,
    address_space: usize,
}

impl LlilSsaMemoryDomain {
    fn from_core(index: usize, domain: CoreSsaMemoryDomain) -> Self {
        Self {
            index,
            address_space: domain.space().index(),
        }
    }
}

#[pymethods]
impl LlilSsaMemoryDomain {
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
pub(crate) struct LlilSsaOperation {
    index: usize,
    opcode: &'static str,
    results: Vec<usize>,
    operands: Vec<usize>,
    width: u32,
    immediate: u64,
    address: Option<Address>,
    address_space: Option<usize>,
}

impl LlilSsaOperation {
    fn from_core(
        body: &CoreSsaBody,
        index: usize,
        operation: &CoreSsaOperation,
    ) -> Result<Self, CoreIlError> {
        let results = operation.results().start()..operation.results().end();
        let results = results.collect();
        let operands = body
            .operation_operands(operation)?
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
impl LlilSsaOperation {
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
    module.add_class::<ArtefactDigest>()?;
    module.add_class::<IrArtefact>()?;
    module.add_class::<IrBlock>()?;
    module.add_class::<IrBlockPredecessors>()?;
    module.add_class::<IrSourceRun>()?;
    module.add_class::<IrMappingRun>()?;
    module.add_class::<PCodeLocation>()?;
    module.add_class::<PCodeOperation>()?;
    module.add_class::<LlilExpression>()?;
    module.add_class::<LlilStatement>()?;
    module.add_class::<LlilSsaValue>()?;
    module.add_class::<LlilSsaValueUses>()?;
    module.add_class::<LlilSsaUse>()?;
    module.add_class::<LlilSsaLiveness>()?;
    module.add_class::<LlilSsaDominance>()?;
    module.add_class::<LlilSsaBlockArgument>()?;
    module.add_class::<LlilSsaEdgeArguments>()?;
    module.add_class::<LlilSsaMemoryDomain>()?;
    module.add_class::<LlilSsaOperation>()?;

    Ok(())
}
