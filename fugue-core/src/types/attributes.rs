use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::ptr;

use rkyv::bytecheck::CheckBytes;
use rkyv::collections::util::{Entry as ArchivedEntry, EntryResolver};
use rkyv::munge::munge;
use rkyv::primitive::{ArchivedF64, ArchivedI64, ArchivedU64};
use rkyv::rancor::{Fallible, Source, fail};
use rkyv::ser::{Allocator, Writer};
use rkyv::string::{ArchivedString, StringResolver};
use rkyv::traits::NoUndef;
use rkyv::validation::ArchiveContext;
use rkyv::vec::{ArchivedVec, VecResolver};
use rkyv::{Archive, Deserialize, Place, Portable, Serialize};
use rustc_hash::FxHashMap;
use thiserror::Error;

pub extern crate serde_json;

use crate::storage::entities::schema::ENTITY_ATTRIBUTES_ID;
use crate::storage::entities::{Entity, EntityId};

pub const ATTRIBUTE_INPUT_PATH: &str = "project.input_path";
pub const ATTRIBUTE_PROJECT_PATH: &str = "project.path";
pub const ATTRIBUTE_ENTRY_POINT: &str = "project.entry_point";
pub const ATTRIBUTE_IMAGE_BASE: &str = "project.image_base";
pub const ATTRIBUTE_ADDRESS_SPACE: &str = "loader.address_space";
pub const ATTRIBUTE_LANGUAGE_VARIANT: &str = "loader.language.variant";

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

unsafe impl NoUndef for ArchivedJsonValueTag {}
unsafe impl Portable for ArchivedJsonValueTag {}

#[repr(u8)]
pub enum ArchivedJsonValue {
    Null,
    Bool(bool),
    I64(ArchivedI64),
    U64(ArchivedU64),
    F64(ArchivedF64),
    String(ArchivedString),
    Array(ArchivedVec<ArchivedJsonValue>),
    Object(ArchivedVec<ArchivedEntry<ArchivedString, ArchivedJsonValue>>),
}

unsafe impl Portable for ArchivedJsonValue {}

#[repr(C)]
struct VarBool(ArchivedJsonValueTag, bool);

#[repr(C)]
struct VarI64(ArchivedJsonValueTag, ArchivedI64);

#[repr(C)]
struct VarU64(ArchivedJsonValueTag, ArchivedU64);

#[repr(C)]
struct VarF64(ArchivedJsonValueTag, ArchivedF64);

#[repr(C)]
struct VarString(ArchivedJsonValueTag, ArchivedString);

#[repr(C)]
struct VarArray(ArchivedJsonValueTag, ArchivedVec<ArchivedJsonValue>);

#[repr(C)]
struct VarObject(
    ArchivedJsonValueTag,
    ArchivedVec<ArchivedEntry<ArchivedString, ArchivedJsonValue>>,
);

#[derive(Debug, Error)]
#[error("invalid discriminant: {0}")]
struct InvalidJsonTag(u8);

unsafe impl<C> CheckBytes<C> for ArchivedJsonValue
where
    C: Fallible + ArchiveContext + ?Sized,
    C::Error: Source,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        // SAFETY: `ArchivedJsonValue` is `#[repr(u8)]`, so the first byte is
        // the discriminant.
        let tag = unsafe { *value.cast::<u8>() };
        match tag {
            0 => Ok(()),
            1 => unsafe {
                let p = value.cast::<VarBool>();
                <bool as CheckBytes<C>>::check_bytes(ptr::addr_of!((*p).1), context)
            },
            2 => unsafe {
                let p = value.cast::<VarI64>();
                <ArchivedI64 as CheckBytes<C>>::check_bytes(ptr::addr_of!((*p).1), context)
            },
            3 => unsafe {
                let p = value.cast::<VarU64>();
                <ArchivedU64 as CheckBytes<C>>::check_bytes(ptr::addr_of!((*p).1), context)
            },
            4 => unsafe {
                let p = value.cast::<VarF64>();
                <ArchivedF64 as CheckBytes<C>>::check_bytes(ptr::addr_of!((*p).1), context)
            },
            5 => unsafe {
                let p = value.cast::<VarString>();
                <ArchivedString as CheckBytes<C>>::check_bytes(ptr::addr_of!((*p).1), context)
            },
            6 => unsafe {
                let p = value.cast::<VarArray>();
                <ArchivedVec<ArchivedJsonValue> as CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            7 => unsafe {
                let p = value.cast::<VarObject>();
                <ArchivedVec<ArchivedEntry<ArchivedString, ArchivedJsonValue>> as CheckBytes<C>>::check_bytes(
                    ptr::addr_of!((*p).1),
                    context,
                )
            },
            other => fail!(InvalidJsonTag(other)),
        }
    }
}

#[repr(transparent)]
pub struct ArchivedAttributeMap(ArchivedVec<ArchivedEntry<ArchivedString, ArchivedJsonValue>>);

unsafe impl Portable for ArchivedAttributeMap {}

unsafe impl<C> CheckBytes<C> for ArchivedAttributeMap
where
    C: Fallible + ArchiveContext + ?Sized,
    C::Error: Source,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe {
            <ArchivedVec<ArchivedEntry<ArchivedString, ArchivedJsonValue>> as CheckBytes<C>>::check_bytes(
                value.cast(),
                context,
            )
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
    String(StringResolver),
    Array(VecResolver),
    Object(VecResolver),
}

impl<'a> Archive for JsonValueRef<'a> {
    type Archived = ArchivedJsonValue;
    type Resolver = JsonValueResolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        match (self.0, resolver) {
            (serde_json::Value::Null, JsonValueResolver::Null) => {
                let out = unsafe { out.cast_unchecked::<ArchivedJsonValueTag>() };
                out.write(ArchivedJsonValueTag::Null);
            }
            (serde_json::Value::Bool(b), JsonValueResolver::Bool) => {
                let out = unsafe { out.cast_unchecked::<VarBool>() };
                munge!(let VarBool(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::Bool);
                payload.write(*b);
            }
            (serde_json::Value::Number(n), JsonValueResolver::I64) => {
                let out = unsafe { out.cast_unchecked::<VarI64>() };
                munge!(let VarI64(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::I64);
                payload.write(ArchivedI64::from_native(n.as_i64().unwrap_or(0)));
            }
            (serde_json::Value::Number(n), JsonValueResolver::U64) => {
                let out = unsafe { out.cast_unchecked::<VarU64>() };
                munge!(let VarU64(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::U64);
                payload.write(ArchivedU64::from_native(n.as_u64().unwrap_or(0)));
            }
            (serde_json::Value::Number(n), JsonValueResolver::F64) => {
                let out = unsafe { out.cast_unchecked::<VarF64>() };
                munge!(let VarF64(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::F64);
                payload.write(ArchivedF64::from_native(n.as_f64().unwrap_or(0.0)));
            }
            (serde_json::Value::String(s), JsonValueResolver::String(r)) => {
                let out = unsafe { out.cast_unchecked::<VarString>() };
                munge!(let VarString(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::String);
                ArchivedString::resolve_from_str(s.as_str(), r, payload);
            }
            (serde_json::Value::Array(arr), JsonValueResolver::Array(r)) => {
                let out = unsafe { out.cast_unchecked::<VarArray>() };
                munge!(let VarArray(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::Array);
                ArchivedVec::resolve_from_len(arr.len(), r, payload);
            }
            (serde_json::Value::Object(obj), JsonValueResolver::Object(r)) => {
                let out = unsafe { out.cast_unchecked::<VarObject>() };
                munge!(let VarObject(tag, payload) = out);
                tag.write(ArchivedJsonValueTag::Object);
                ArchivedVec::resolve_from_len(obj.len(), r, payload);
            }
            _ => unreachable!(),
        }
    }
}

impl<'a, S> Serialize<S> for JsonValueRef<'a>
where
    S: Fallible + Writer + Allocator + ?Sized,
    S::Error: Source,
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
                ArchivedString::serialize_from_str(s.as_str(), serializer)?,
            ),
            serde_json::Value::Array(arr) => {
                JsonValueResolver::Array(ArchivedVec::<ArchivedJsonValue>::serialize_from_iter::<
                    JsonValueRef<'_>,
                    _,
                    _,
                >(
                    arr.iter().map(JsonValueRef), serializer
                )?)
            }
            serde_json::Value::Object(obj) => {
                JsonValueResolver::Object(ArchivedVec::<
                    ArchivedEntry<ArchivedString, ArchivedJsonValue>,
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

impl<'a> Archive for AttributeEntryRef<'a> {
    type Archived = ArchivedEntry<ArchivedString, ArchivedJsonValue>;
    type Resolver = EntryResolver<StringResolver, JsonValueResolver>;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        munge!(let ArchivedEntry { key, value } = out);
        ArchivedString::resolve_from_str(self.key, resolver.key, key);
        self.value.resolve(resolver.value, value);
    }
}

impl<'a, S> Serialize<S> for AttributeEntryRef<'a>
where
    S: Fallible + Writer + Allocator + ?Sized,
    S::Error: Source,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(EntryResolver {
            key: ArchivedString::serialize_from_str(self.key, serializer)?,
            value: self.value.serialize(serializer)?,
        })
    }
}

impl Archive for AttributeMap {
    type Archived = ArchivedAttributeMap;
    type Resolver = VecResolver;

    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let out = unsafe {
            out.cast_unchecked::<ArchivedVec<ArchivedEntry<ArchivedString, ArchivedJsonValue>>>()
        };
        ArchivedVec::resolve_from_len(self.0.len(), resolver, out);
    }
}

impl<S> Serialize<S> for AttributeMap
where
    S: Fallible + Writer + Allocator + ?Sized,
    S::Error: Source,
{
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        ArchivedVec::<ArchivedEntry<ArchivedString, ArchivedJsonValue>>::serialize_from_iter::<
            AttributeEntryRef<'_>,
            _,
            _,
        >(
            self.0.iter().map(|(k, v)| AttributeEntryRef {
                key: k.as_str(),
                value: JsonValueRef(v),
            }),
            serializer,
        )
    }
}

impl<D> Deserialize<serde_json::Value, D> for ArchivedJsonValue
where
    D: Fallible + ?Sized,
    D::Error: Source,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<serde_json::Value, D::Error> {
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

impl<D> Deserialize<AttributeMap, D> for ArchivedAttributeMap
where
    D: Fallible + ?Sized,
    D::Error: Source,
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
            $crate::types::attributes::serde_json::json!({ $($json)* }),
        );
        $crate::attributes!(@accum $attrs; $($($rest)*)?);
    };
    (@accum $attrs:ident; $key:expr => $value:expr $(, $($rest:tt)*)?) => {
        $attrs.set_attr($key, $value);
        $crate::attributes!(@accum $attrs; $($($rest)*)?);
    };
    ( $($input:tt)* ) => {{
        #[allow(unused_mut)]
        let mut attrs = $crate::types::attributes::AttributeMap::new();
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
                "list": [1, "two", false, null, { "deep": [3.14] }]
            }),
        ];

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&amap).unwrap();
        let bmap = rkyv::from_bytes::<AttributeMap, rkyv::rancor::Error>(&bytes).unwrap();

        assert_eq!(amap, bmap);
    }
}
