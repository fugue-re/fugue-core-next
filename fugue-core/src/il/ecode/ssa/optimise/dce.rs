use crate::il::ecode::ssa::ECodeSsaIr;

impl ECodeSsaIr {
    pub(crate) fn eliminate_dead_code(&mut self) {
        let reachable = self.compute_reachability();
        for (index, operation) in self.operations.iter_mut().enumerate() {
            if !reachable.operations[index] {
                operation.make_undefined();
            }
        }
    }
}
