use std::error::Error;

use thiserror::Error as ThisError;

use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{IlArtefact, IlError};
use crate::ir::{CodeBlockTable, FunctionId, FunctionTable};
use crate::lifter::Language;
use crate::platform::Platform;
use crate::storage::SegmentStorage;
use crate::types::common::Revision;

pub struct IlGenerationContext<'a> {
    arch: &'a Arch,
    platform: &'a Platform,
    functions: &'a FunctionTable,
    blocks: &'a CodeBlockTable,
    segments: &'a SegmentStorage,
    input_revision: Revision,
}

impl<'a> IlGenerationContext<'a> {
    pub fn new(
        arch: &'a Arch,
        platform: &'a Platform,
        functions: &'a FunctionTable,
        blocks: &'a CodeBlockTable,
        segments: &'a SegmentStorage,
        input_revision: Revision,
    ) -> Self {
        Self {
            arch,
            platform,
            functions,
            blocks,
            segments,
            input_revision,
        }
    }

    pub fn arch(&self) -> &Arch {
        self.arch
    }

    pub fn platform(&self) -> &Platform {
        self.platform
    }

    pub fn language(&self) -> &'static Language {
        self.arch.language()
    }

    pub fn functions(&self) -> &'a FunctionTable {
        self.functions
    }

    pub fn blocks(&self) -> &'a CodeBlockTable {
        self.blocks
    }

    pub fn segments(&self) -> &'a SegmentStorage {
        self.segments
    }

    pub fn input_revision(&self) -> Revision {
        self.input_revision
    }
}

#[derive(Debug, ThisError)]
pub enum IlGenerationError {
    #[error(transparent)]
    Il(#[from] IlError),
    #[error(transparent)]
    Producer(Box<dyn Error + Send + Sync>),
}

impl IlGenerationError {
    pub fn producer(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Producer(Box::new(error))
    }
}

pub trait IlRootProducer: IlArtefact {
    fn produce(
        function: FunctionId,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self, IlGenerationError>;
}

pub trait IlConversion: IlArtefact {
    type Source: IlArtefact;

    fn convert(
        source: &Self::Source,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self, IlGenerationError>;
}
