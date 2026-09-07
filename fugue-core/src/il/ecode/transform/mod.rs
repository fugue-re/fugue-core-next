use graph::{PCodeToECodeGraphMapper, remap_source_spans};
use lifter::{PCodeToECodeLiftScratch, PCodeToECodeLifter};
use ssa::{PCodeToECodeSsaLifter, PCodeToECodeSsaScratch};

use crate::arch::Arch;
use crate::il::common::{
    IlArtefact, IlError, IlGenerationContext, IlGenerationError, IlGraph, IlMetadata, IlTransformer,
};
use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeOptimiser};
use crate::il::pcode::PCodeIr;
use crate::platform::Platform;

mod buffer;
mod graph;
mod lifter;
mod ssa;

#[derive(Debug, Default)]
pub struct PCodeToECode {
    graph_mapper: PCodeToECodeGraphMapper,
    lift_scratch: PCodeToECodeLiftScratch,
    ssa_scratch: PCodeToECodeSsaScratch,
}

impl PCodeToECode {
    pub fn transform(
        &mut self,
        source: &PCodeIr,
        arch: &Arch,
        platform: &Platform,
    ) -> Result<ECodeIr, IlError> {
        let metadata = IlMetadata::new(
            source.metadata().function(),
            source.metadata().input_revision(),
        );
        let builder = ECodeBuilder::new(metadata, IlGraph::default());
        let (buffer, operation_map) =
            PCodeToECodeLifter::new(source, arch, &mut self.lift_scratch)?.lift(platform)?;
        let graph = self.graph_mapper.remap(source, &operation_map)?;
        let parent_spans = operation_map.parent_spans()?;
        let source_spans = remap_source_spans(source, &operation_map)?;

        let mut ecode = PCodeToECodeSsaLifter::new(
            buffer,
            graph,
            source_spans,
            parent_spans,
            builder,
            &mut self.ssa_scratch,
        )
        .lift()?;
        ecode.rewrite(ECodeOptimiser);

        #[cfg(debug_assertions)]
        {
            ecode.verify().expect("optimised ECode fails verification");
        }

        Ok(ecode)
    }
}

impl IlTransformer for PCodeToECode {
    type Input = PCodeIr;
    type Output = ECodeIr;

    fn transform(
        &mut self,
        source: &Self::Input,
        context: &IlGenerationContext<'_>,
    ) -> Result<Self::Output, IlGenerationError> {
        let ecode = PCodeToECode::transform(self, source, context.arch(), context.platform())?;

        #[cfg(debug_assertions)]
        if !context.is_speculative() {
            ecode
                .verify()
                .expect("transformed ECode fails verification");
        }

        Ok(ecode)
    }
}
