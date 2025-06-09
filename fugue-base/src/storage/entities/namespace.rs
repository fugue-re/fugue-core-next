use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use uuid::Uuid;

use super::EntityKeyPrefix;

static NAMESPACE_REGISTRY: LazyLock<NamespaceRegistry> = LazyLock::new(NamespaceRegistry::new);

#[derive(Debug, Clone)]
pub struct Namespace {
    name: String,
    entity_hashes: Arc<DashMap<Uuid, EntityKeyPrefix>>,
}

impl Namespace {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entity_hashes: Arc::new(DashMap::new()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }

    pub fn get_entity_hash(&self, entity_uuid: Uuid) -> EntityKeyPrefix {
        // Try to get from cache first
        if let Some(hash) = self.entity_hashes.get(&entity_uuid) {
            return *hash;
        }

        // Compute hash: blake3(NAMESPACE + ENTITY_UUID)
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.name.as_bytes());
        hasher.update(entity_uuid.as_bytes());

        let full_hash = hasher.finalize();

        // Truncate to 16 bytes
        let mut truncated_hash = [0u8; 16];
        truncated_hash.copy_from_slice(&full_hash.as_bytes()[0..16]);

        // Cache the result
        self.entity_hashes.insert(entity_uuid, truncated_hash);

        // Also update global registry for reverse lookups (debugging/introspection)
        NAMESPACE_REGISTRY.insert_mapping(truncated_hash, self.clone(), entity_uuid);

        truncated_hash
    }
}

impl AsRef<Namespace> for Namespace {
    fn as_ref(&self) -> &Namespace {
        self
    }
}

impl AsRef<str> for Namespace {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl PartialEq for Namespace {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Namespace {}

impl std::hash::Hash for Namespace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl From<&str> for Namespace {
    fn from(s: &str) -> Self {
        Namespace::new(s)
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// Simplified namespace registry for reverse lookups only
#[derive(Debug)]
struct NamespaceRegistry {
    // Only reverse mapping from hash to (namespace, entity_uuid) for debugging/introspection
    reverse_mapping: DashMap<[u8; 16], (Namespace, Uuid)>,
}

impl NamespaceRegistry {
    fn new() -> Self {
        Self {
            reverse_mapping: DashMap::new(),
        }
    }

    fn insert_mapping(&self, hash: [u8; 16], namespace: Namespace, entity_uuid: Uuid) {
        self.reverse_mapping.insert(hash, (namespace, entity_uuid));
    }

    fn lookup_namespace_and_uuid(&self, hash: &[u8; 16]) -> Option<(Namespace, Uuid)> {
        self.reverse_mapping.get(hash).map(|entry| entry.clone())
    }

    fn clear(&self) {
        self.reverse_mapping.clear();
    }
}
