use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::control::CancellationToken;
use crate::arch::Arch;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlError, IlExprId, IlIndexRange, IlMetadata, IlValueId,
};
use crate::il::common::{IlConversion, IlGenerationContext, IlGenerationError};
use crate::il::ecode::ssa::{ECodeSsaBuilder, ECodeSsaIr, ECodeSsaOptimiser};
use crate::il::ecode::{ECodeIr, PCodeToECode};
use crate::il::pcode::{FlagId, PCodeCanonicaliser, PCodeError, RegisterId};
use crate::ir::IncompleteFunction;
use crate::platform::Platform;
use crate::storage::SegmentStorage;
use crate::storage::segments::space::AddressSpaceId;
use crate::types::common::Revision;

mod blocks;
mod build;
mod domains;
mod spans;

#[derive(Debug)]
enum ExpressionStep {
    Build(IlExprId),
    Visit(IlExprId),
}

#[derive(Debug, Default)]
pub struct ECodeToSsa {
    expression_operands: Vec<IlValueId>,
    expression_steps: Vec<ExpressionStep>,
    pcode_to_ecode: PCodeToECode,
    statement_operands: Vec<IlValueId>,
}

impl IlConversion for ECodeSsaIr {
    type Source = ECodeIr;

    fn convert(
        source: &Self::Source,
        _context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self, IlGenerationError> {
        Ok(ECodeToSsa::default().transform_optimised(source, cancellation)?)
    }
}

impl ECodeToSsa {
    pub fn transform(
        &mut self,
        source: &ECodeIr,
        cancellation: &CancellationToken,
    ) -> Result<ECodeSsaIr, IlError> {
        cancellation.check()?;

        let metadata = IlMetadata::new(
            source.metadata().function(),
            source.metadata().input_revision(),
        );
        let mut builder = ECodeSsaBuilder::new(metadata, source.graph().clone());
        let mut construction = ECodeSsaConstruction::new(
            source,
            &mut builder,
            &mut self.expression_operands,
            &mut self.expression_steps,
            &mut self.statement_operands,
        );

        construction.build(cancellation)?;
        drop(construction);

        builder.build(cancellation)
    }

    pub fn transform_optimised(
        &mut self,
        source: &ECodeIr,
        cancellation: &CancellationToken,
    ) -> Result<ECodeSsaIr, IlError> {
        let mut ir = self.transform(source, cancellation)?;
        ir.rewrite(ECodeSsaOptimiser);

        if cfg!(debug_assertions) {
            ir.verify().expect("optimised ECode SSA fails verification");
        }

        Ok(ir)
    }

    pub(crate) fn build_incomplete_function(
        &mut self,
        arch: &Arch,
        platform: &Platform,
        function: &IncompleteFunction,
        segments: &SegmentStorage,
        input_revision: Revision,
        cancellation: &CancellationToken,
    ) -> Result<ECodeSsaIr, PCodeError> {
        let mut canonicaliser = PCodeCanonicaliser::default();
        let lifted = canonicaliser.build_incomplete_function(
            arch.language(),
            function,
            segments,
            input_revision,
            cancellation,
        )?;
        let ecode = self
            .pcode_to_ecode
            .transform(&lifted, arch, platform, cancellation)?;
        Ok(self.transform_optimised(&ecode, cancellation)?)
    }
}

struct ECodeSsaConstruction<'a, 'b> {
    source: &'a ECodeIr,
    builder: &'b mut ECodeSsaBuilder,
    values: Vec<Option<IlValueId>>,
    built_expressions: Vec<IlExprId>,
    expression_operands: &'b mut Vec<IlValueId>,
    expression_steps: &'b mut Vec<ExpressionStep>,
    block_argument_domains: BTreeMap<IlValueId, SsaDomain>,
    block_arguments: Vec<Vec<(SsaDomain, IlValueId)>>,
    domain_widths: BTreeMap<SsaDomain, u32>,
    entry_block: Option<IlBlockId>,
    input_domains: Vec<(SsaDomain, u32)>,
    blocks: Vec<Option<IlBlock>>,
    edge_arguments: Vec<Vec<IlValueId>>,
    statement_operands: &'b mut Vec<IlValueId>,
    statement_ranges: Vec<IlIndexRange>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SsaDomain {
    Flag(FlagId),
    Memory(AddressSpaceId),
    Register(RegisterId),
}

impl SsaDomain {
    const fn undefined_immediate(&self) -> u64 {
        match self {
            Self::Register(register) => register.value(),
            Self::Flag(flag) => flag.value(),
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

impl<'a, 'b> ECodeSsaConstruction<'a, 'b> {
    fn new(
        source: &'a ECodeIr,
        builder: &'b mut ECodeSsaBuilder,
        expression_operands: &'b mut Vec<IlValueId>,
        expression_steps: &'b mut Vec<ExpressionStep>,
        statement_operands: &'b mut Vec<IlValueId>,
    ) -> Self {
        Self {
            source,
            builder,
            values: vec![None; source.expressions().len()],
            built_expressions: Vec::new(),
            expression_operands,
            expression_steps,
            block_argument_domains: BTreeMap::new(),
            block_arguments: vec![Vec::new(); source.graph().blocks().len()],
            domain_widths: BTreeMap::new(),
            entry_block: None,
            input_domains: Vec::new(),
            blocks: vec![None; source.graph().blocks().len()],
            edge_arguments: vec![Vec::new(); source.graph().successors().len()],
            statement_operands,
            statement_ranges: vec![IlIndexRange::EMPTY; source.statements().len()],
        }
    }
}

#[cfg(test)]
mod test;
