use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::ptr;

use rustc_hash::FxHashMap;
use thiserror::Error;

pub extern crate serde_json;

use crate::storage::entities::schema::ENTITY_ATTRIBUTES_ID;
use crate::storage::entities::{Entity, EntityId};

pub const ATTRIBUTE_FILE_PATH: &str = "project.input_path";
pub const ATTRIBUTE_PROJECT_PATH: &str = "project.path";
pub const ATTRIBUTE_ENTRY_POINT: &str = "project.entry_point";
pub const ATTRIBUTE_IMAGE_BASE: &str = "project.image_base";
pub const ATTRIBUTE_ADDRESS_SPACE: &str = "loader.address_space";

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct AttributeMap(FxHashMap<String, serde_json::Value>);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ArchivedJsonValueTag {
    Null = 0,
    Bool = 1,
    I64 = 2,
    U64 = 3,
    F64 = 4,
    String = 5,
    Array = 6,
    Object = 7,
}

unsafe impl rkyv::traits::NoUndef for ArchivedJsonValueTag {}
unsafe impl rkyv::Portable for ArchivedJsonValueTag {}

#[repr(u8)]
pub enum ArchivedJsonValue {
    Null,
    Bool(bool),
    I64(rkyv::primitive::ArchivedI64),
    U64(rkyv::primitive::ArchivedU64),
    F64(rkyv::primitive::ArchivedF64),
    String(rkyv::string::ArchivedString),
    Array(rkyv::vec::ArchivedVec<ArchivedJsonValue>),
    Object(
        rkyv::vec::ArchivedVec<
            rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
        >,
    ),
}

unsafe impl rkyv::Portable for ArchivedJsonValue {}

#[repr(C)]
struct VarBool(ArchivedJsonValueTag, bool);

#[repr(C)]
struct VarI64(ArchivedJsonValueTag, rkyv::primitive::ArchivedI64);

#[repr(C)]
struct VarU64(ArchivedJsonValueTag, rkyv::primitive::ArchivedU64);

#[repr(C)]
struct VarF64(ArchivedJsonValueTag, rkyv::primitive::ArchivedF64);

#[repr(C)]
struct VarString(ArchivedJsonValueTag, rkyv::string::ArchivedString);

#[repr(C)]
struct VarArray(
    ArchivedJsonValueTag,
    rkyv::vec::ArchivedVec<ArchivedJsonValue>,
);

#[repr(C)]
struct VarObject(
    ArchivedJsonValueTag,
    rkyv::vec::ArchivedVec<
        rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
    >,
);

#[derive(Debug, Error)]
#[error("invalid discriminant: {0}")]
struct InvalidJsonTag(u8);

unsafe impl<C> rkyv::bytecheck::CheckBytes<C> for ArchivedJsonValue
where
    C: rkyv::rancor::Fallible + rkyv::validation::ArchiveContext + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        // SAFETY: `ArchivedJsonValue` is `#[repr(u8)]`, so the first byte is
        // the discriminant.
        let tag = unsafe { *value.cast::<u8>() };
        match tag {
            0 => Ok(()),
            1 => unsafe {
                let p = value.cast::<VarBool>();
                <bool as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            2 => unsafe {
                let p = value.cast::<VarI64>();
                <rkyv::primitive::ArchivedI64 as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            3 => unsafe {
                let p = value.cast::<VarU64>();
                <rkyv::primitive::ArchivedU64 as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            4 => unsafe {
                let p = value.cast::<VarF64>();
                <rkyv::primitive::ArchivedF64 as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            5 => unsafe {
                let p = value.cast::<VarString>();
                <rkyv::string::ArchivedString as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            6 => unsafe {
                let p = value.cast::<VarArray>();
                <rkyv::vec::ArchivedVec<ArchivedJsonValue> as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            7 => unsafe {
                let p = value.cast::<VarObject>();
                <rkyv::vec::ArchivedVec<
                    rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
                > as rkyv::bytecheck::CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1), context
                )
            },
            other => rkyv::rancor::fail!(InvalidJsonTag(other)),
        }
    }
}

#[repr(transparent)]
pub struct ArchivedAttributeMap(
    rkyv::vec::ArchivedVec<
        rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
    >,
);

unsafe impl rkyv::Portable for ArchivedAttributeMap {}

unsafe impl<C> rkyv::bytecheck::CheckBytes<C> for ArchivedAttributeMap
where
    C: rkyv::rancor::Fallible + rkyv::validation::ArchiveContext + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe {
            <rkyv::vec::ArchivedVec<
                rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
            > as rkyv::bytecheck::CheckBytes<C>>::check_bytes(value.cast(), context)
        }
    }
}

#[derive(Clone, Copy)]
struct JsonValueRef<'a>(&'a serde_json::Value);

enum JsonValueResolver {
    Null,
    Bool,
    I64,
    U64,
    F64,
    String(rkyv::string::StringResolver),
    Array(rkyv::vec::VecResolver),
    Object(rkyv::vec::VecResolver),
}

impl<'a> rkyv::Archive for JsonValueRef<'a> {
    type Archived = ArchivedJsonValue;
    type Resolver = JsonValueResolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        match (self.0, resolver) {
            (serde_json::Value::Null, JsonValueResolver::Null) => {
                let out = unsafe { out.cast_unchecked::<ArchivedJsonValueTag>() };
                out.write(ArchivedJsonValueTag::Null);
            }
            (serde_json::Value::Bool(b), JsonValueResolver::Bool) => {
                let out = unsafe { out.cast_unchecked::<VarBool>() };
                rkyv::munge::munge!(let VarBool(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::Bool);
                payload.write(*b);
            }
            (serde_json::Value::Number(n), JsonValueResolver::I64) => {
                let out = unsafe { out.cast_unchecked::<VarI64>() };
                rkyv::munge::munge!(let VarI64(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::I64);
                payload.write(rkyv::primitive::ArchivedI64::from_native(
                    n.as_i64().unwrap_or(0),
                ));
            }
            (serde_json::Value::Number(n), JsonValueResolver::U64) => {
                let out = unsafe { out.cast_unchecked::<VarU64>() };
                rkyv::munge::munge!(let VarU64(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::U64);
                payload.write(rkyv::primitive::ArchivedU64::from_native(
                    n.as_u64().unwrap_or(0),
                ));
            }
            (serde_json::Value::Number(n), JsonValueResolver::F64) => {
                let out = unsafe { out.cast_unchecked::<VarF64>() };
                rkyv::munge::munge!(let VarF64(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::F64);
                payload.write(rkyv::primitive::ArchivedF64::from_native(
                    n.as_f64().unwrap_or(0.0),
                ));
            }
            (serde_json::Value::String(s), JsonValueResolver::String(r)) => {
                let out = unsafe { out.cast_unchecked::<VarString>() };
                rkyv::munge::munge!(let VarString(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::String);
                rkyv::string::ArchivedString::resolve_from_str(s.as_str(), r, payload);
            }
            (serde_json::Value::Array(arr), JsonValueResolver::Array(r)) => {
                let out = unsafe { out.cast_unchecked::<VarArray>() };
                rkyv::munge::munge!(let VarArray(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::Array);
                rkyv::vec::ArchivedVec::resolve_from_len(arr.len(), r, payload);
            }
            (serde_json::Value::Object(obj), JsonValueResolver::Object(r)) => {
                let out = unsafe { out.cast_unchecked::<VarObject>() };
                rkyv::munge::munge!(let VarObject(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::Object);
                rkyv::vec::ArchivedVec::resolve_from_len(obj.len(), r, payload);
            }
            _ => unreachable!(),
        }
    }
}

impl<'a, S> rkyv::Serialize<S> for JsonValueRef<'a>
where
    S: rkyv::rancor::Fallible + rkyv::ser::Writer + rkyv::ser::Allocator + ?Sized,
    S::Error: rkyv::rancor::Source,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(match self.0 {
            serde_json::Value::Null => JsonValueResolver::Null,
            serde_json::Value::Bool(_) => JsonValueResolver::Bool,
            serde_json::Value::Number(n) => {
                if n.as_i64().is_some() {
                    JsonValueResolver::I64
                } else if n.as_u64().is_some() {
                    JsonValueResolver::U64
                } else {
                    JsonValueResolver::F64
                }
            }
            serde_json::Value::String(s) => JsonValueResolver::String(
                rkyv::string::ArchivedString::serialize_from_str(s.as_str(), serializer)?,
            ),
            serde_json::Value::Array(arr) => {
                JsonValueResolver::Array(
                    rkyv::vec::ArchivedVec::<ArchivedJsonValue>::serialize_from_iter::<
                        JsonValueRef<'_>,
                        _,
                        _,
                    >(arr.iter().map(JsonValueRef), serializer)?,
                )
            }
            serde_json::Value::Object(obj) => {
                JsonValueResolver::Object(rkyv::vec::ArchivedVec::<
                    rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
                >::serialize_from_iter::<AttributeEntryRef<'_>, _, _>(
                    obj.iter().map(|(k, v)| AttributeEntryRef {
                        key: k.as_str(),
                        value: JsonValueRef(v),
                    }),
                    serializer,
                )?)
            }
        })
    }
}

#[derive(Clone, Copy)]
struct AttributeEntryRef<'a> {
    key: &'a str,
    value: JsonValueRef<'a>,
}

impl<'a> rkyv::Archive for AttributeEntryRef<'a> {
    type Archived = rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>;
    type Resolver =
        rkyv::collections::util::EntryResolver<rkyv::string::StringResolver, JsonValueResolver>;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        rkyv::munge::munge!(let rkyv::collections::util::Entry { key, value } = out);
        rkyv::string::ArchivedString::resolve_from_str(self.key, resolver.key, key);
        self.value.resolve(resolver.value, value);
    }
}

impl<'a, S> rkyv::Serialize<S> for AttributeEntryRef<'a>
where
    S: rkyv::rancor::Fallible + rkyv::ser::Writer + rkyv::ser::Allocator + ?Sized,
    S::Error: rkyv::rancor::Source,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(rkyv::collections::util::EntryResolver {
            key: rkyv::string::ArchivedString::serialize_from_str(self.key, serializer)?,
            value: self.value.serialize(serializer)?,
        })
    }
}

impl rkyv::Archive for AttributeMap {
    type Archived = ArchivedAttributeMap;
    type Resolver = rkyv::vec::VecResolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        let out = unsafe {
            out.cast_unchecked::<rkyv::vec::ArchivedVec<
                rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
            >>()
        };
        rkyv::vec::ArchivedVec::resolve_from_len(self.0.len(), resolver, out);
    }
}

impl<S> rkyv::Serialize<S> for AttributeMap
where
    S: rkyv::rancor::Fallible + rkyv::ser::Writer + rkyv::ser::Allocator + ?Sized,
    S::Error: rkyv::rancor::Source,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        rkyv::vec::ArchivedVec::<
            rkyv::collections::util::Entry<rkyv::string::ArchivedString, ArchivedJsonValue>,
        >::serialize_from_iter::<AttributeEntryRef<'_>, _, _>(
            self.0.iter().map(|(k, v)| AttributeEntryRef {
                key: k.as_str(),
                value: JsonValueRef(v),
            }),
            serializer,
        )
    }
}

impl<D> rkyv::Deserialize<serde_json::Value, D> for ArchivedJsonValue
where
    D: rkyv::rancor::Fallible + ?Sized,
    D::Error: rkyv::rancor::Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<serde_json::Value, D::Error> {
        let _ = &deserializer;

        Ok(match self {
            ArchivedJsonValue::Null => serde_json::Value::Null,
            ArchivedJsonValue::Bool(b) => serde_json::Value::Bool(*b),
            ArchivedJsonValue::I64(i) => serde_json::Value::Number(i.to_native().into()),
            ArchivedJsonValue::U64(u) => serde_json::Value::Number(u.to_native().into()),
            ArchivedJsonValue::F64(f) => serde_json::Number::from_f64(f.to_native())
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            ArchivedJsonValue::String(s) => serde_json::Value::String(s.as_str().to_owned()),
            ArchivedJsonValue::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr.iter() {
                    out.push(item.deserialize(deserializer)?);
                }
                serde_json::Value::Array(out)
            }
            ArchivedJsonValue::Object(obj) => {
                let mut map = serde_json::Map::new();
                for entry in obj.iter() {
                    map.insert(
                        entry.key.as_str().to_owned(),
                        entry.value.deserialize(deserializer)?,
                    );
                }
                serde_json::Value::Object(map)
            }
        })
    }
}

impl<D> rkyv::Deserialize<AttributeMap, D> for ArchivedAttributeMap
where
    D: rkyv::rancor::Fallible + ?Sized,
    D::Error: rkyv::rancor::Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<AttributeMap, D::Error> {
        let archived = self.0.as_slice();
        let mut map = FxHashMap::with_capacity_and_hasher(archived.len(), Default::default());
        for entry in archived {
            map.insert(
                entry.key.as_str().to_owned(),
                entry.value.deserialize(deserializer)?,
            );
        }
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
    (@accum $attrs:ident;) => {};
    (@accum $attrs:ident; $key:expr => { $($json:tt)* } $(, $($rest:tt)*)?) => {
        $attrs.set_attr(
            $key,
            $crate::types::serde_json::json!({ $($json)* }),
        );
        $crate::attributes!(@accum $attrs; $($($rest)*)?);
    };
    (@accum $attrs:ident; $key:expr => $value:expr $(, $($rest:tt)*)?) => {
        $attrs.set_attr($key, $value);
        $crate::attributes!(@accum $attrs; $($($rest)*)?);
    };
    ( $($input:tt)* ) => {{
        #[allow(unused_mut)]
        let mut attrs = $crate::types::AttributeMap::new();
        $crate::attributes!(@accum attrs; $($input)*);
        attrs
    }};
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use super::AttributeMap;

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
    fn attrs_macro_with_json() {
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

    #[test]
    fn test_attrs_macro_mixed_forms() {
        let amap = attributes![
            "path" => "/x",
            "config" => {
                "version": 1,
                "flags": ["a", "b"]
            },
            "count" => -7i64,
            "tag" => serde_json::Value::Null,
        ];

        assert_eq!(amap.get_attr::<String>("path"), Some("/x".to_owned()));
        assert_eq!(amap.get_attr::<i64>("count"), Some(-7));
        assert!(amap.contains("config"));
        assert!(amap.contains("tag"));
    }

    #[test]
    fn test_rkyv_roundtrip() {
        let amap = attributes![
            "null" => serde_json::Value::Null,
            "bool" => true,
            "neg" => -42i64,
            "pos" => 18_000_000_000u64,
            "float" => 1.5f64,
            "short" => "hi",
            "long" => "this string is definitely longer than the inline capacity, forcing out-of-line storage",
            "nested" => serde_json::json!({
                "list": [1, "two", false, null, { "deep": [3.125] }]
            }),
        ];

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&amap).unwrap();
        let bmap = rkyv::from_bytes::<AttributeMap, rkyv::rancor::Error>(&bytes).unwrap();

        assert_eq!(amap, bmap);
    }
}
