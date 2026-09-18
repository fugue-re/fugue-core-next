use graph::PCodeToECodeGraphMapper;
use lifter::{PCodeToECodeLiftScratch, PCodeToECodeLifter};
use ssa::PCodeToECodeSsaScratch;

use crate::arch::Arch;
use crate::il::common::{
    IlArtefact, IlError, IlGenerationContext, IlGenerationError, IlTransformer,
};
use crate::il::ecode::{ECodeIr, ECodeOptimiser};
use crate::il::pcode::PCodeIr;
use crate::platform::Platform;

mod graph;
mod lifter;
mod ssa;
mod state;

#[derive(Debug, Default)]
pub struct PCodeToECode {
    graph_mapper: PCodeToECodeGraphMapper,
    lift_scratch: PCodeToECodeLiftScratch,
    ssa_scratch: PCodeToECodeSsaScratch,
}

impl PCodeToECode {
    pub fn transform(
        &mut self,
        arch: &Arch,
        platform: &Platform,
        source: &PCodeIr,
    ) -> Result<ECodeIr, IlError> {
        let mut ecode = PCodeToECodeLifter::new(
            arch,
            platform,
            source,
            &mut self.graph_mapper,
            &mut self.lift_scratch,
            &mut self.ssa_scratch,
        )?
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
        let ecode = PCodeToECode::transform(self, context.arch(), context.platform(), source)?;

        #[cfg(debug_assertions)]
        if !context.is_speculative() {
            ecode
                .verify()
                .expect("transformed ECode fails verification");
        }

        Ok(ecode)
    }
}
