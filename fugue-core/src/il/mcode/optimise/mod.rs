use crate::il::common::{IlArtefact, IlRewrite, IlValueId};
use crate::il::mcode::MCodeIr;

mod compact;
mod fold;
mod required;

pub(crate) use compact::MCodeCompaction;
pub(crate) use fold::MCodeConstantFolding;

pub(crate) struct MCodeOptimiser<'a> {
    required_values: &'a [IlValueId],
}

impl IlRewrite<MCodeIr> for MCodeOptimiser<'_> {
    fn rewrite(&mut self, ir: &mut MCodeIr) {
        ir.rewrite(MCodeConstantFolding);
        ir.rewrite(MCodeCompaction::new(self.required_values));
    }
}

impl<'a> MCodeOptimiser<'a> {
    pub(crate) const fn new(required_values: &'a [IlValueId]) -> Self {
        Self { required_values }
    }
}

#[cfg(test)]
mod test;
