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

struct AttributeValue<T>(T);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Decode, Encode)]
#[repr(u8)]
enum AttributeKind {
    Null,
    Bool,
    Signed,
    Unsigned,
    Float,
    String,
    Array,
    Object,
}

impl Encode for AttributeValue<&'_ serde_json::Value> {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        use serde_json::Value;

        match self.0 {
            Value::Null => {
                AttributeKind::Null.encode(encoder)?;
            }
            Value::Bool(b) => {
                AttributeKind::Bool.encode(encoder)?;
                b.encode(encoder)?;
            }
            Value::Number(num) => {
                if num.is_i64() {
                    AttributeKind::Signed.encode(encoder)?;
                    i64::from(num.as_i64().unwrap()).encode(encoder)?
                } else if num.is_u64() {
                    AttributeKind::Unsigned.encode(encoder)?;
                    u64::from(num.as_u64().unwrap()).encode(encoder)?
                } else {
                    AttributeKind::Float.encode(encoder)?;
                    f64::from(num.as_f64().unwrap()).encode(encoder)?
                }
            }
            Value::String(s) => {
                AttributeKind::String.encode(encoder)?;
                s.encode(encoder)?
            }
            Value::Array(arr) => {
                AttributeKind::Array.encode(encoder)?;
                arr.len().encode(encoder)?;
                for item in arr.iter() {
                    AttributeValue(item).encode(encoder)?;
                }
            }
            Value::Object(obj) => {
                AttributeKind::Object.encode(encoder)?;
                obj.len().encode(encoder)?;
                for (key, value) in obj.iter() {
                    key.encode(encoder)?;
                    AttributeValue(value).encode(encoder)?;
                }
            }
        }

        Ok(())
    }
}

impl<C> Decode<C> for AttributeValue<serde_json::Value> {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use serde_json::value::Number;
        use serde_json::{Map, Value};

        let kind = AttributeKind::decode(decoder)?;
        let value = match kind {
            AttributeKind::Null => Value::Null,
            AttributeKind::Bool => Value::Bool(bool::decode(decoder)?),
            AttributeKind::Signed => Value::Number(Number::from(i64::decode(decoder)?)),
            AttributeKind::Unsigned => Value::Number(Number::from(u64::decode(decoder)?)),
            AttributeKind::Float => {
                serde_json::Value::Number(Number::from_f64(f64::decode(decoder)?).unwrap())
            }
            AttributeKind::String => Value::String(String::decode(decoder)?),
            AttributeKind::Array => {
                let len = usize::decode(decoder)?;
                let mut arr = Vec::with_capacity(len);
                for _ in 0..len {
                    arr.push(AttributeValue::<Value>::decode(decoder)?.0);
                }
                Value::Array(arr)
            }
            AttributeKind::Object => {
                let len = usize::decode(decoder)?;
                let mut obj = Map::default();
                for _ in 0..len {
                    let key = String::decode(decoder)?;
                    let value = AttributeValue::<Value>::decode(decoder)?.0;
                    obj.insert(key, value);
                }
                Value::Object(obj)
            }
        };

        Ok(Self(value))
    }
}

impl Encode for AttributeMap {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.len().encode(encoder)?;
        for (key, value) in &self.0 {
            key.encode(encoder)?;
            AttributeValue(value).encode(encoder)?;
        }

        Ok(())
    }
}

impl<C> Decode<C> for AttributeMap {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let len = usize::decode(decoder)?;

        let mut map = FxHashMap::default();
        map.reserve(len);

        for _ in 0..len {
            let key = String::decode(decoder)?;
            let AttributeValue(value) = AttributeValue::<serde_json::Value>::decode(decoder)?;
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
    // Handle embedded maps with braces
    ( $($key:expr => { $($json:tt)* }),* $(,)? ) => {
        {
            #[allow(unused_mut)]
            let mut attrs = $crate::types::attributes::AttributeMap::new();
            $(
                attrs.set_attr($key, serde_json::json!({ $($json)* }));
            )*
            attrs
        }
    };
    // Handle mixed values (some with braces, some without)
    ( $($key:expr => $value:tt),* $(,)? ) => {
        {
            #[allow(unused_mut)]
            let mut attrs = $crate::types::attributes::AttributeMap::new();
            $(
                attrs.set_attr($key, $crate::attributes_value!($value));
            )*
            attrs
        }
    };
}

// Helper macro to handle different value types
#[macro_export]
macro_rules! attributes_value {
    // If it's a braced block, treat as JSON
    ({ $($json:tt)* }) => {
        serde_json::json!({ $($json)* })
    };
    // Otherwise, use the value as-is
    ($value:expr) => {
        $value
    };
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
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

    #[test]
    fn teat_attrs_macro_with_json() {
        let amap = attributes![
            "project" => {
                "name": "My Project",
                "version": {
                    "major": "1",
                    "minor": "0",
                    "patch": "0"
                }
            }
        ];

        #[derive(Deserialize, Serialize)]
        struct MyProject {
            name: String,
            version: MyProjectVersion,
        }

        #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
        struct MyProjectVersion {
            major: String,
            minor: String,
            patch: String,
        }

        let my_project = amap.get_attr::<MyProject>("project");

        assert!(my_project.is_some());

        let my_project = my_project.unwrap();
        assert_eq!(my_project.name, "My Project");
        assert_eq!(
            my_project.version,
            MyProjectVersion {
                major: "1".to_owned(),
                minor: "0".to_owned(),
                patch: "0".to_owned(),
            }
        );
    }
}
