use crate::il::common::{IlArtefact, IlRewrite};
use crate::il::ecode::ECodeIr;

mod compact;
mod fold;
mod required;

pub(crate) use compact::ECodeCompaction;
pub(crate) use fold::ECodeConstantFolding;

pub(crate) struct ECodeOptimiser;

impl IlRewrite<ECodeIr> for ECodeOptimiser {
    fn rewrite(&mut self, ir: &mut ECodeIr) {
        ir.rewrite(ECodeConstantFolding);
        ir.rewrite(ECodeCompaction);
    }
}

#[cfg(test)]
mod test;
