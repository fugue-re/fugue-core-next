use std::borrow::Borrow;
use std::collections::hash_map::Entry;

use bincode::{Decode, Encode};
use rustc_hash::FxHashMap;

use crate::storage::entities::common::ENTITY_ATTRIBUTES_ID;
use crate::storage::entities::{Entity, EntityId};

pub const ATTRIBUTE_FILE_PATH: &str = "project.input_path";
pub const ATTRIBUTE_PROJECT_PATH: &str = "project.path";

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct AttributeMap(FxHashMap<String, serde_json::Value>);

impl Encode for AttributeMap {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use bincode::serde::Compat;

        self.0.len().encode(encoder)?;
        for (key, value) in &self.0 {
            key.encode(encoder)?;
            Compat(value).encode(encoder)?;
        }

        Ok(())
    }
}

impl<C> Decode<C> for AttributeMap {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::serde::Compat;

        let len = usize::decode(decoder)?;

        let mut map = FxHashMap::default();
        map.reserve(len);

        for _ in 0..len {
            let key = String::decode(decoder)?;
            let Compat(value) = Compat::<serde_json::Value>::decode(decoder)?;
            map.insert(key, value);
        }

        Ok(Self(map))
    }
}

impl Entity for AttributeMap {
    const ID: EntityId = ENTITY_ATTRIBUTES_ID;
}

impl From<AttributeMap> for FxHashMap<String, serde_json::Value> {
    fn from(value: AttributeMap) -> Self {
        value.0
    }
}

impl From<FxHashMap<String, serde_json::Value>> for AttributeMap {
    fn from(value: FxHashMap<String, serde_json::Value>) -> Self {
        Self(value)
    }
}

pub trait Attribute: serde::de::DeserializeOwned + serde::Serialize {}

impl<T> Attribute for T where T: serde::de::DeserializeOwned + serde::Serialize {}

impl AttributeMap {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn get_attr<T>(&self, key: impl Borrow<str>) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.0
            .get(key.borrow())
            .and_then(|val| serde_json::from_value(val.clone()).ok())
    }

    pub fn set_attr(&mut self, key: impl ToString, val: impl serde::Serialize) {
        self.0.insert(key.to_string(), serde_json::json!(val));
    }

    pub fn merge(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    pub fn merge_vacant(&mut self, other: &Self) {
        for (key, value) in other.0.iter() {
            if let Entry::Vacant(entry) = self.0.entry(key.to_owned()) {
                entry.insert(value.to_owned());
            }
        }
    }

    pub fn contains(&self, key: impl Borrow<str>) -> bool {
        self.0.contains_key(key.borrow())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[macro_export]
macro_rules! attributes {
    ( $($key:expr => $value:expr),* $(,)? ) => {
        {
            #[allow(unused_mut)]
            let mut attrs = $crate::types::attributes::AttributeMap::new();
            $(
                attrs.set_attr($key, $value);
            )*
            attrs
        }
    };
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use uuid::Uuid;

    #[test]
    fn test_attrs_macro() {
        let guid = Uuid::now_v7();
        let amap = attributes![
            "guid" => guid,
            "path" => "/path/to/my/executable.elf",
        ];

        assert!(amap.contains("path"));
        assert_eq!(
            amap.get_attr::<PathBuf>("path"),
            Some(PathBuf::from("/path/to/my/executable.elf"))
        );

        assert_eq!(amap.get_attr::<Uuid>("guid"), Some(guid));
    }
}
