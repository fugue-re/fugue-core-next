use crate::il::common::verify::StructureVerifierError;
use crate::il::common::{IlAnalysis, IlFormId, IlGraph, IlParentSpan, IlRewrite, IlSourceSpan};
use crate::ir::FunctionId;
use crate::storage::entities::schema::EntityCodec;
use crate::types::{EstimateSize, Revision};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[repr(transparent)]
pub struct IlSchemaVersion(u16);

impl IlSchemaVersion {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u16 {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlMetadata {
    function: FunctionId,
    input_revision: Revision,
}

impl IlMetadata {
    pub fn new(function: FunctionId, input_revision: impl Into<Revision>) -> Self {
        Self {
            function,
            input_revision: input_revision.into(),
        }
    }

    pub const fn function(&self) -> FunctionId {
        self.function
    }

    pub const fn input_revision(&self) -> Revision {
        self.input_revision
    }

    pub fn set_input_revision(&mut self, revision: Revision) {
        self.input_revision = revision;
    }

    pub fn with_input_revision(mut self, revision: Revision) -> Self {
        self.set_input_revision(revision);
        self
    }
}

pub trait IlArtefact: EstimateSize + Send + Sync + Sized + 'static {
    const FORM_IDENTIFIER: &'static str;
    const FORM: IlFormId = IlFormId::from_static(Self::FORM_IDENTIFIER);

    fn metadata(&self) -> &IlMetadata;

    fn analyse<A: IlAnalysis<Self>>(&self) -> A {
        A::analyse(self)
    }

    fn rewrite<R: IlRewrite<Self>>(&mut self, mut rewrite: R) {
        rewrite.rewrite(self);
        #[cfg(debug_assertions)]
        self.verify_after_rewrite();
    }

    #[cfg(debug_assertions)]
    fn verify_after_rewrite(&self) {}
}

pub trait ControlFlowIl: IlArtefact {
    fn graph(&self) -> &IlGraph;

    fn verify_structure<E>(
        &self,
        source_spans: &[IlSourceSpan],
        parent_spans: Option<&[IlParentSpan]>,
        node_count: usize,
    ) -> Result<(), E>
    where
        E: StructureVerifierError,
    {
        self.graph().verify().map_err(E::from_structure)?;
        self.graph()
            .verify_node_bounds(node_count)
            .map_err(E::from_structure)?;
        IlSourceSpan::verify(source_spans, node_count).map_err(E::from_structure)?;
        if let Some(parent_spans) = parent_spans {
            IlParentSpan::verify(parent_spans, node_count).map_err(E::from_structure)?;
        }
        Ok(())
    }
}

pub trait PersistableIl: IlArtefact + EntityCodec {
    const SCHEMA: IlSchemaVersion;

    fn metadata_mut(&mut self) -> &mut IlMetadata;
}
