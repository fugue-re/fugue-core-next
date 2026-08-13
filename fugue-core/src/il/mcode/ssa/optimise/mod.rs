use crate::il::common::{IlArtefact, IlRewrite, IlValueId};
use crate::il::mcode::ssa::MCodeSsaIr;

mod compact;
mod fold;
mod required;

pub(crate) use compact::MCodeSsaCompaction;
pub(crate) use fold::MCodeSsaConstantFolding;

pub(crate) struct MCodeSsaOptimiser<'a> {
    required_values: &'a [IlValueId],
}

impl IlRewrite<MCodeSsaIr> for MCodeSsaOptimiser<'_> {
    fn rewrite(&mut self, ir: &mut MCodeSsaIr) {
        ir.rewrite(MCodeSsaConstantFolding);
        ir.rewrite(MCodeSsaCompaction::new(self.required_values));
    }
}

impl<'a> MCodeSsaOptimiser<'a> {
    pub(crate) const fn new(required_values: &'a [IlValueId]) -> Self {
        Self { required_values }
    }
}

#[cfg(test)]
mod test;
