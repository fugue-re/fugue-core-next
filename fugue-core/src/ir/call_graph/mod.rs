use crate::ir::Address;
use crate::storage::entities::schema::ENTITY_KEY_CALL_GRAPH_FORWARD_ID;
use crate::storage::entities::{EntityKey, EntityKeyCodec, EntityKeyId};

mod index;
pub(crate) use index::{
    ATTRIBUTE_CALL_GRAPH_INDEX_CACHE_SIZE, CallGraphStaging, DEFAULT_CALL_GRAPH_INDEX_CACHE_BYTES,
};
pub use index::{CallGraphAddressIterator, CallGraphEdgeIterator, CallGraphIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallGraphEdgeKey {
    source: Address,
    target: Address,
}

impl CallGraphEdgeKey {
    pub fn new(source: Address, target: Address) -> Self {
        Self { source, target }
    }

    pub fn source(&self) -> Address {
        self.source
    }

    pub fn target(&self) -> Address {
        self.target
    }
}

impl EntityKeyCodec for CallGraphEdgeKey {
    fn decode(input: &mut &[u8]) -> Option<Self> {
        let source = Address::decode(input)?;
        let target = Address::decode(input)?;
        Some(Self::new(source, target))
    }

    fn encode(&self, output: &mut impl Extend<u8>) {
        self.source.encode(output);
        self.target.encode(output);
    }
}

impl EntityKey for CallGraphEdgeKey {
    const ID: EntityKeyId = ENTITY_KEY_CALL_GRAPH_FORWARD_ID;
}
