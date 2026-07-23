use super::reachability::ECodeSsaReachability;
use crate::il::common::{IlArtefact, IlRewrite};
use crate::il::ecode::ssa::ECodeSsaIr;

pub(crate) struct ECodeSsaDeadCodeElimination;

impl IlRewrite<ECodeSsaIr> for ECodeSsaDeadCodeElimination {
    fn rewrite(&mut self, ir: &mut ECodeSsaIr) {
        let reachable = ir.analyse::<ECodeSsaReachability>();
        for (index, operation) in ir.operations.iter_mut().enumerate() {
            if !reachable.operation_is_reachable(index) {
                operation.make_undefined();
            }
        }
    }
}
