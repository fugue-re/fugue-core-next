use std::borrow::Borrow;
use std::collections::hash_map::Entry;

use rkyv::rancor::Fallible;
use rkyv::{Archive, Place, Serialize};
use rustc_hash::FxHashMap;

pub extern crate serde_json;

use crate::storage::entities::schema::ENTITY_ATTRIBUTES_ID;
use crate::storage::entities::{Entity, EntityId};

pub const ATTRIBUTE_FILE_PATH: &str = "project.input_path";
pub const ATTRIBUTE_PROJECT_PATH: &str = "project.path";
pub const ATTRIBUTE_ENTRY_POINT: &str = "project.entry_point";
pub const ATTRIBUTE_IMAGE_BASE: &str = "project.image_base";

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct AttributeMap(FxHashMap<String, serde_json::Value>);

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    <__S as rkyv::rancor::Fallible>::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(bounds(__C: rkyv::validation::ArchiveContext)))]
pub enum JsonValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    String(String),
    Array(#[rkyv(omit_bounds)] Vec<JsonValue>),
    Object(#[rkyv(omit_bounds)] Vec<(String, JsonValue)>),
}

impl From<serde_json::Value> for JsonValue {
    fn from(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => JsonValue::Null,
            serde_json::Value::Bool(b) => JsonValue::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    JsonValue::I64(i)
                } else if let Some(u) = n.as_u64() {
                    JsonValue::U64(u)
                } else {
                    JsonValue::F64(n.as_f64().unwrap_or(0.0))
                }
            }
            serde_json::Value::String(s) => JsonValue::String(s),
            serde_json::Value::Array(a) => {
                JsonValue::Array(a.into_iter().map(Into::into).collect())
            }
            serde_json::Value::Object(o) => {
                JsonValue::Object(o.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

impl From<JsonValue> for serde_json::Value {
    fn from(v: JsonValue) -> Self {
        match v {
            JsonValue::Null => serde_json::Value::Null,
            JsonValue::Bool(b) => serde_json::Value::Bool(b),
            JsonValue::I64(i) => serde_json::Value::Number(i.into()),
            JsonValue::U64(u) => serde_json::Value::Number(u.into()),
            JsonValue::F64(f) => serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            JsonValue::String(s) => serde_json::Value::String(s),
            JsonValue::Array(a) => {
                serde_json::Value::Array(a.into_iter().map(Into::into).collect())
            }
            JsonValue::Object(o) => {
                serde_json::Value::Object(o.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

type AttributeMapInner = Vec<(String, JsonValue)>;

#[repr(transparent)]
pub struct ArchivedAttributeMap(rkyv::Archived<AttributeMapInner>);

unsafe impl rkyv::Portable for ArchivedAttributeMap {}
unsafe impl rkyv::traits::NoUndef for ArchivedAttributeMap {}

unsafe impl<C: rkyv::rancor::Fallible + ?Sized> rkyv::bytecheck::CheckBytes<C>
    for ArchivedAttributeMap
where
    rkyv::Archived<AttributeMapInner>: rkyv::bytecheck::CheckBytes<C>,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { <rkyv::Archived<AttributeMapInner>>::check_bytes(value.cast(), context) }
    }
}

impl Archive for AttributeMap {
    type Archived = ArchivedAttributeMap;
    type Resolver = <AttributeMapInner as Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let out_inner = unsafe { out.cast_unchecked::<rkyv::Archived<AttributeMapInner>>() };
        let entries = self
            .0
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect::<AttributeMapInner>();
        entries.resolve(resolver, out_inner);
    }
}

impl<
    S: Fallible<Error: rkyv::rancor::Source> + ?Sized + rkyv::ser::Allocator + rkyv::ser::Writer,
> Serialize<S> for AttributeMap
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let entries = self
            .0
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect::<AttributeMapInner>();
        entries.serialize(serializer)
    }
}

impl<D: Fallible + ?Sized> rkyv::Deserialize<AttributeMap, D> for ArchivedAttributeMap
where
    D::Error: rkyv::rancor::Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<AttributeMap, D::Error> {
        let entries =
            rkyv::Deserialize::<AttributeMapInner, D>::deserialize(&self.0, deserializer)?;
        let map = entries
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect::<FxHashMap<String, serde_json::Value>>();
        Ok(AttributeMap(map))
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

#[macro_export]
macro_rules! attributes_value {
    ({ $($json:tt)* }) => {
        $crate::types::attributes::serde_json::json!({ $($json)* })
    };
    ($value:expr) => {
        $value
    };
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};
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
