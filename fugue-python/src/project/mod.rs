use std::path::PathBuf;
use std::sync::Arc;

use fugue_core::engine::AnalysisEngine;
use fugue_core::il::common::{
    IlArtefact as CoreIlArtefact, IlArtefact, IlBlock as CoreIlBlock, IlBlockId as CoreIlBlockId,
    IlBlockProperties as CoreIlBlockProperties, IlDominance as CoreDominance,
    IlDominanceFrontier as CoreDominanceFrontier, IlError as CoreIlError, IlFormId as CoreIlFormId,
    IlGraph as CoreIlGraph, IlMetadata as CoreIlMetadata, IlParentSpan as CoreIlParentSpan,
    IlSourceSpan as CoreIlSourceSpan, IlSsaDef as CoreIlSsaDef, IlValueId as CoreIlValueId,
    PersistableIl,
};
use fugue_core::il::ecode::{
    ECodeBlockArg as CoreECodeBlockArg, ECodeDomain as CoreECodeDomain, ECodeIr as CoreECodeIr,
    ECodeLiveness as CoreECodeLiveness, ECodeMemoryDomain as CoreECodeMemoryDomain,
    ECodeOp as CoreECodeOp, ECodeUse as CoreECodeUse, ECodeUses as CoreECodeUses,
    ECodeValue as CoreECodeValue,
};
use fugue_core::il::mcode::{
    MCodeBlockArg as CoreMCodeBlockArg, MCodeIr as CoreMCodeIr,
    MCodeMemoryDomain as CoreMCodeMemoryDomain, MCodeOp as CoreMCodeOp,
    MCodeValue as CoreMCodeValue, MCodeVar as CoreMCodeVar, MCodeVarId as CoreMCodeVarId,
    MCodeVarKind as CoreMCodeVarKind,
};
use fugue_core::il::pcode::{
    PCodeIr as CorePCodeIr, PCodeLocation as CorePCodeLocation, PCodeOp as CorePCodeOp,
    PCodeOpcode as CorePCodeOpcode,
};
use fugue_core::ir::{Address as CoreAddress, FunctionId as CoreFunctionId};
use fugue_core::project::{ChangeRecord, Project as CoreProject};
use fugue_core::queries::QueryReader;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::address::Address;
use crate::binary::Binary;
use crate::errors::{BindingError, project_error};

mod common;
mod ecode;
mod mcode;
mod pcode;

use common::*;
use ecode::*;
use mcode::*;
use pcode::*;

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
            "mcode" => Ok(<CoreMCodeIr as IlArtefact>::FORM),
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
            .map(|ir| ir.map(PCodeIr::from_core))
            .map_err(project_error)
    }

    fn ecode(&self, function: &Function) -> PyResult<Option<ECodeIr>> {
        self.reader
            .ecode(function.id)
            .map(|ir| ir.map(ECodeIr::from_core))
            .map_err(project_error)
    }

    fn mcode(&self, function: &Function) -> PyResult<Option<MCodeIr>> {
        self.reader
            .mcode(function.id)
            .map(|ir| ir.map(MCodeIr::from_core))
            .map_err(project_error)
    }

    fn has_lifted(&self, function: &Function, form: &str) -> PyResult<bool> {
        let form = Self::parse_form(form)?;
        let project = self.reader.project().map_err(project_error)?;
        if form == <CorePCodeIr as IlArtefact>::FORM {
            project.pcode(function.id).map(|ir| ir.is_some())
        } else if form == <CoreECodeIr as IlArtefact>::FORM {
            project.ecode(function.id).map(|ir| ir.is_some())
        } else if form == <CoreMCodeIr as IlArtefact>::FORM {
            project.mcode(function.id).map(|ir| ir.is_some())
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
        } else if form == <CoreMCodeIr as IlArtefact>::FORM {
            self.reader
                .mcode(function.id)
                .map(|ir| ir.map(|ir| ir.display().to_string()))
                .map_err(project_error)
        } else {
            Ok(None)
        }
    }

    fn ecode_value_uses(&self, function: &Function) -> PyResult<Option<Vec<ECodeValueUses>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).value_uses().map(Some)
    }

    fn ecode_uses_for_value(
        &self,
        function: &Function,
        value: usize,
    ) -> PyResult<Option<Vec<ECodeUse>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).uses_for_value(value).map(Some)
    }

    fn ecode_liveness(&self, function: &Function) -> PyResult<Option<Vec<ECodeLiveness>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).liveness().map(Some)
    }

    fn ecode_live_in(&self, function: &Function, block: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).live_in(block).map(Some)
    }

    fn ecode_live_out(&self, function: &Function, block: usize) -> PyResult<Option<Vec<usize>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).live_out(block).map(Some)
    }

    fn ecode_dominance(&self, function: &Function) -> PyResult<Option<Vec<IlDominance>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).dominance().map(Some)
    }

    fn ecode_dominance_frontier(
        &self,
        function: &Function,
        block: usize,
    ) -> PyResult<Option<Vec<usize>>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).dominance_frontier(block).map(Some)
    }

    fn ecode_dominates(
        &self,
        function: &Function,
        dominator: usize,
        block: usize,
    ) -> PyResult<Option<bool>> {
        let Some(ir) = self.reader.ecode(function.id).map_err(project_error)? else {
            return Ok(None);
        };
        ECodeIr::from_core(ir).dominates(dominator, block).map(Some)
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

pub(crate) fn add_classes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Project>()?;
    module.add_class::<Function>()?;
    module.add_class::<IlMetadata>()?;
    module.add_class::<IlGraph>()?;
    module.add_class::<PCodeIr>()?;
    module.add_class::<ECodeIr>()?;
    module.add_class::<MCodeIr>()?;
    module.add_class::<IlBlock>()?;
    module.add_class::<IlBlockPredecessors>()?;
    module.add_class::<IlSourceSpan>()?;
    module.add_class::<IlParentSpan>()?;
    module.add_class::<PCodeLocation>()?;
    module.add_class::<PCodeOp>()?;
    module.add_class::<ECodeDomain>()?;
    module.add_class::<ECodeValue>()?;
    module.add_class::<ECodeValueUses>()?;
    module.add_class::<ECodeUse>()?;
    module.add_class::<ECodeLiveness>()?;
    module.add_class::<IlDominance>()?;
    module.add_class::<ECodeBlockArg>()?;
    module.add_class::<ECodeEdgeArgs>()?;
    module.add_class::<ECodeMemoryDomain>()?;
    module.add_class::<ECodeOp>()?;
    module.add_class::<MCodeVar>()?;
    module.add_class::<MCodeValue>()?;
    module.add_class::<MCodeBlockArg>()?;
    module.add_class::<MCodeEdgeArgs>()?;
    module.add_class::<MCodeMemoryDomain>()?;
    module.add_class::<MCodeOp>()?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use fugue_core::loader::Loader;
    use fugue_core::project::Project as CoreProject;

    use super::*;

    #[test]
    fn il_wrappers_share_query_allocations() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fugue-core/tests/ls.elf");
        let loader = Loader::from_file(fixture).expect("the fixture loads");
        let project = CoreProject::new_transient(&loader).expect("the project opens");
        let engine = AnalysisEngine::new(project).expect("the engine starts");
        engine.analyse().expect("analysis completes");
        let reader = engine.query_reader().expect("a reader is available");
        let function = reader
            .project()
            .expect("the project is readable")
            .functions()
            .iter()
            .next()
            .expect("the fixture recovers a function")
            .id();

        let pcode = reader
            .pcode(function)
            .expect("PCode is readable")
            .expect("PCode exists");
        let pcode_first = PCodeIr::from_core(Arc::clone(&pcode));
        let pcode_second = PCodeIr::from_core(pcode);
        assert!(Arc::ptr_eq(&pcode_first.inner, &pcode_second.inner));

        let ecode = reader
            .ecode(function)
            .expect("ECode is readable")
            .expect("ECode exists");
        let ecode_first = ECodeIr::from_core(Arc::clone(&ecode));
        let ecode_second = ECodeIr::from_core(ecode);
        assert!(Arc::ptr_eq(&ecode_first.inner, &ecode_second.inner));

        let mcode = reader
            .mcode(function)
            .expect("MCode is readable")
            .expect("MCode exists");
        let mcode_first = MCodeIr::from_core(Arc::clone(&mcode));
        let mcode_second = MCodeIr::from_core(mcode);
        assert!(Arc::ptr_eq(&mcode_first.inner, &mcode_second.inner));
    }
}
