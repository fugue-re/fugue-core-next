use std::collections::BTreeSet;
use std::ops::Bound;

use super::{CallGraphEdgeKey, InverseCallGraphEdgeKey, PreparedCallGraphBatch};
use crate::ir::Address;
use crate::storage::entities::EntityStorageError;

#[derive(Default)]
pub struct CallGraphIndex {
    forward: BTreeSet<CallGraphEdgeKey>,
    // pub(crate) solely so the consistency verifier in the facade test module can
    // enumerate the inverse index without a production-only accessor.
    pub(crate) inverse: BTreeSet<InverseCallGraphEdgeKey>,
}

impl CallGraphIndex {
    pub(crate) fn callees(
        &self,
        caller: Address,
        after: Option<Address>,
    ) -> impl Iterator<Item = Result<Address, EntityStorageError>> + '_ {
        let start = after.map_or_else(
            || Bound::Included(CallGraphEdgeKey::minimum_for(caller)),
            |after| Bound::Excluded(CallGraphEdgeKey::new(caller, after)),
        );
        self.forward
            .range((start, Bound::Unbounded))
            .take_while(move |edge| edge.source() == caller)
            .map(|&edge| Ok(edge.target()))
    }

    pub(crate) fn callers(
        &self,
        callee: Address,
        after: Option<Address>,
    ) -> impl Iterator<Item = Result<Address, EntityStorageError>> + '_ {
        let start = after.map_or_else(
            || Bound::Included(InverseCallGraphEdgeKey::minimum_for(callee)),
            |after| Bound::Excluded(InverseCallGraphEdgeKey::new(after, callee)),
        );
        self.inverse
            .range((start, Bound::Unbounded))
            .take_while(move |edge| edge.callee() == callee)
            .map(|&edge| Ok(edge.caller()))
    }

    pub(crate) fn edges(
        &self,
        after: Option<CallGraphEdgeKey>,
    ) -> impl Iterator<Item = Result<CallGraphEdgeKey, EntityStorageError>> + '_ {
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        self.forward
            .range((start, Bound::Unbounded))
            .map(|&edge| Ok(edge))
    }

    pub(crate) fn publish(&mut self, batch: PreparedCallGraphBatch) {
        for edge in batch.edges {
            let inverse = InverseCallGraphEdgeKey::new(edge.key.source(), edge.key.target());
            if edge.present {
                self.forward.insert(edge.key);
                self.inverse.insert(inverse);
            } else {
                self.forward.remove(&edge.key);
                self.inverse.remove(&inverse);
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.forward.clear();
        self.inverse.clear();
    }

    pub(crate) fn insert_edge(&mut self, caller: Address, callee: Address) {
        self.forward.insert(CallGraphEdgeKey::new(caller, callee));
        self.inverse
            .insert(InverseCallGraphEdgeKey::new(caller, callee));
    }

    pub(crate) fn remove_edge(&mut self, caller: Address, callee: Address) {
        self.forward.remove(&CallGraphEdgeKey::new(caller, callee));
        self.inverse
            .remove(&InverseCallGraphEdgeKey::new(caller, callee));
    }
}
