use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::control::CancellationToken;
use crate::il::common::{
    IlArtefact, IlBlock, IlBlockId, IlConverter, IlError, IlExprId, IlGenerationContext,
    IlGenerationError, IlIndexRange, IlMetadata, IlValueId,
};
use crate::il::ecode::ECodeIr;
use crate::il::ecode::ssa::{ECodeSsaBuilder, ECodeSsaDomain, ECodeSsaIr, ECodeSsaOptimiser};

mod blocks;
mod build;
mod domains;
mod spans;

#[derive(Debug)]
enum ECodeSsaExpressionStep {
    Build(IlExprId),
    Visit(IlExprId),
}

#[derive(Debug, Default)]
pub struct ECodeToSsa {
    expression_operands: Vec<IlValueId>,
    expression_steps: Vec<ECodeSsaExpressionStep>,
    statement_operands: Vec<IlValueId>,
}

impl IlConverter for ECodeToSsa {
    type Input = ECodeIr;
    type Output = ECodeSsaIr;

    fn convert(
        &mut self,
        source: &Self::Input,
        _context: &IlGenerationContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        Ok(self.transform_optimised(source, cancellation)?)
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
}

struct ECodeSsaConstruction<'a, 'b> {
    source: &'a ECodeIr,
    builder: &'b mut ECodeSsaBuilder,
    values: Vec<Option<IlValueId>>,
    built_expressions: Vec<IlExprId>,
    expression_operands: &'b mut Vec<IlValueId>,
    expression_steps: &'b mut Vec<ECodeSsaExpressionStep>,
    block_argument_domains: BTreeMap<IlValueId, ECodeSsaDomain>,
    block_arguments: Vec<Vec<(ECodeSsaDomain, IlValueId)>>,
    domain_widths: BTreeMap<ECodeSsaDomain, u32>,
    entry_block: Option<IlBlockId>,
    input_domains: Vec<(ECodeSsaDomain, u32)>,
    blocks: Vec<Option<IlBlock>>,
    edge_arguments: Vec<Vec<IlValueId>>,
    statement_operands: &'b mut Vec<IlValueId>,
    statement_ranges: Vec<IlIndexRange>,
}

#[derive(Debug, Default)]
struct ECodeSsaDomains {
    widths: BTreeMap<ECodeSsaDomain, u32>,
    definitions: BTreeMap<ECodeSsaDomain, Vec<IlBlockId>>,
    reads: BTreeSet<ECodeSsaDomain>,
}

impl<'a, 'b> ECodeSsaConstruction<'a, 'b> {
    fn new(
        source: &'a ECodeIr,
        builder: &'b mut ECodeSsaBuilder,
        expression_operands: &'b mut Vec<IlValueId>,
        expression_steps: &'b mut Vec<ECodeSsaExpressionStep>,
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
