use std::collections::{BTreeMap, BTreeSet};

use fugue_lifter::runtime::language::Language;

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlError, IlHeader, IlIndexRange, IlValueId,
};
use crate::il::ecode::ssa::{
    ECODE_SSA_SCHEMA_VERSION, ECodeSsaBuilder, ECodeSsaIr, ECodeSsaOptimiser,
};
use crate::il::ecode::{ECodeIr, PCodeToECode};
use crate::il::pcode::{PCodeCanonicaliser, PCodeError};
use crate::ir::IncompleteFunction;
use crate::storage::SegmentStorage;
use crate::storage::segments::space::AddressSpaceId;

mod blocks;
mod domains;
mod lower;
mod spans;

#[derive(Debug, Default)]
pub struct ECodeToSsa;

impl ECodeToSsa {
    pub fn transform(
        &mut self,
        source: &ECodeIr,
        cancellation: &CancellationToken,
    ) -> Result<ECodeSsaIr, IlError> {
        cancellation.check()?;

        let header = IlHeader::new(
            source.header().function(),
            ECODE_SSA_SCHEMA_VERSION,
            source.header().input_revision(),
        );
        let mut builder = ECodeSsaBuilder::new(header, source.graph().clone());
        let mut construction = SsaConstruction::new(source, &mut builder);

        construction.construct(cancellation)?;
        drop(construction);

        builder.build(cancellation)
    }

    pub(crate) fn build_incomplete_function(
        &mut self,
        language: &'static Language,
        function: &IncompleteFunction,
        segments: &SegmentStorage,
        input_revision: u64,
        cancellation: &CancellationToken,
    ) -> Result<ECodeSsaIr, PCodeError> {
        let mut canonicaliser = PCodeCanonicaliser::default();
        let lifted = canonicaliser.build_incomplete_function(
            language,
            function,
            segments,
            input_revision,
            cancellation,
        )?;
        let ecode = PCodeToECode.transform(&lifted, cancellation)?;
        let mut ir = self.transform(&ecode, cancellation)?;
        ir.rewrite(ECodeSsaOptimiser);

        Ok(ir)
    }
}

struct SsaConstruction<'a, 'b> {
    source: &'a ECodeIr,
    builder: &'b mut ECodeSsaBuilder,
    values: Vec<Option<IlValueId>>,
    block_argument_domains: BTreeMap<IlValueId, SsaDomain>,
    block_arguments: Vec<Vec<(SsaDomain, IlValueId)>>,
    domain_widths: BTreeMap<SsaDomain, u32>,
    entry_block: Option<IlBlockId>,
    input_domains: Vec<(SsaDomain, u32)>,
    blocks: Vec<Option<IlBlock>>,
    edge_arguments: Vec<Vec<IlValueId>>,
    statement_ranges: Vec<IlIndexRange>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SsaDomain {
    Flag(u64),
    Memory(AddressSpaceId),
    Register(u64),
}

impl SsaDomain {
    const fn undefined_immediate(&self) -> u64 {
        match self {
            Self::Register(register) | Self::Flag(register) => *register,
            Self::Memory(space) => space.index() as u64,
        }
    }
}

#[derive(Debug, Default)]
struct SsaDomains {
    widths: BTreeMap<SsaDomain, u32>,
    definitions: BTreeMap<SsaDomain, Vec<IlBlockId>>,
    reads: BTreeSet<SsaDomain>,
}

impl<'a, 'b> SsaConstruction<'a, 'b> {
    fn new(source: &'a ECodeIr, builder: &'b mut ECodeSsaBuilder) -> Self {
        Self {
            source,
            builder,
            values: vec![None; source.expressions().len()],
            block_argument_domains: BTreeMap::new(),
            block_arguments: vec![Vec::new(); source.graph().blocks().len()],
            domain_widths: BTreeMap::new(),
            entry_block: None,
            input_domains: Vec::new(),
            blocks: vec![None; source.graph().blocks().len()],
            edge_arguments: vec![Vec::new(); source.graph().successors().len()],
            statement_ranges: vec![IlIndexRange::EMPTY; source.statements().len()],
        }
    }
}

#[cfg(test)]
mod test;
