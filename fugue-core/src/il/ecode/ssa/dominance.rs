use crate::il::common::{IlDominance, IlDominanceFrontier};
use crate::il::ecode::ssa::ECodeSsaIr;

impl ECodeSsaIr {
    pub fn dominance(&self) -> IlDominance {
        let Some(entry) = self.graph().entry_block() else {
            return IlDominance::default();
        };

        IlDominance::from_blocks(self.graph().blocks(), self.graph().successors(), entry)
    }

    pub fn dominance_frontiers(&self) -> IlDominanceFrontier {
        self.dominance()
            .frontiers(self.graph().blocks(), self.graph().successors())
    }
}
