mod compact;
mod dce;
mod fold;
mod reachability;

pub(crate) use compact::ECodeSsaCompaction;
pub(crate) use dce::ECodeSsaDeadCodeElimination;
pub(crate) use fold::ECodeSsaConstantFolding;

use crate::il::common::{IlArtefact, IlRewrite};
use crate::il::ecode::ssa::ECodeSsaIr;

pub(crate) struct ECodeSsaOptimiser;

impl IlRewrite<ECodeSsaIr> for ECodeSsaOptimiser {
    fn rewrite(&mut self, ir: &mut ECodeSsaIr) {
        ir.rewrite(ECodeSsaConstantFolding);
        ir.rewrite(ECodeSsaDeadCodeElimination);
        ir.rewrite(ECodeSsaCompaction);
    }
}

#[cfg(test)]
mod test;
