use std::error::Error;

use thiserror::Error as ThisError;

use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{IlArtefact, IlError};
use crate::ir::{CodeBlockTable, FunctionId, FunctionTable, IncompleteFunction};
use crate::lifter::Language;
use crate::platform::Platform;
use crate::storage::SegmentStorage;
use crate::types::common::Revision;

pub struct IlGenerationContext<'a> {
    subject: IlSubject<'a>,
    arch: &'a Arch,
    platform: &'a Platform,
    functions: &'a FunctionTable,
    blocks: &'a CodeBlockTable,
    segments: &'a SegmentStorage,
    input_revision: Revision,
}

impl<'a> IlGenerationContext<'a> {
    pub fn new(
        subject: IlSubject<'a>,
        arch: &'a Arch,
        platform: &'a Platform,
        functions: &'a FunctionTable,
        blocks: &'a CodeBlockTable,
        segments: &'a SegmentStorage,
        input_revision: Revision,
    ) -> Self {
        Self {
            subject,
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

    pub fn subject(&self) -> IlSubject<'a> {
        self.subject
    }

    pub fn function(&self) -> FunctionId {
        self.subject.function()
    }

    pub fn is_speculative(&self) -> bool {
        self.subject.is_speculative()
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

#[derive(Debug, Clone, Copy)]
pub enum IlSubject<'a> {
    Admitted(FunctionId),
    Speculative {
        function: &'a IncompleteFunction,
        input_revision: Revision,
    },
}

impl IlSubject<'_> {
    pub fn function(&self) -> FunctionId {
        match self {
            Self::Admitted(function) => *function,
            Self::Speculative { .. } => FunctionId::INVALID,
        }
    }

    pub fn is_speculative(&self) -> bool {
        matches!(self, Self::Speculative { .. })
    }
}

pub trait IlProducer: Default + Send + 'static {
    type Output: IlArtefact;

    fn produce(
        &mut self,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError>;
}

pub trait IlTransformer: Default + Send + 'static {
    type Input: IlArtefact;
    type Output: IlArtefact;

    fn transform(
        &mut self,
        source: &Self::Input,
        context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError>;
}
