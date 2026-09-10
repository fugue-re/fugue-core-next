use std::path::PathBuf;

use fugue_core::ir::RawAddress;
use fugue_core::loader::elf::ATTRIBUTE_OVERRIDE_SEGMENT_PERMISSIONS;
use fugue_core::types::AttributeMap;
use fugue_core::types::attributes::{
    ATTRIBUTE_ADDRESS_SPACE, ATTRIBUTE_ENTRY_POINT, ATTRIBUTE_IMAGE_BASE, ATTRIBUTE_INPUT_PATH,
    ATTRIBUTE_PROJECT_PATH,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::convert::{address_from_any, address_space_id};
use crate::errors::BindingError;

fn json_from_py(object: &Bound<'_, PyAny>) -> PyResult<JsonValue> {
    if object.is_none() {
        return Ok(JsonValue::Null);
    }

    if let Ok(value) = object.extract::<bool>() {
        return Ok(serde_json::json!(value));
    }

    if let Ok(value) = object.extract::<i64>() {
        return Ok(serde_json::json!(value));
    }

    if let Ok(value) = object.extract::<u64>() {
        return Ok(serde_json::json!(value));
    }

    if let Ok(value) = object.extract::<f64>() {
        return Ok(serde_json::json!(value));
    }

    if let Ok(value) = object.extract::<String>() {
        return Ok(serde_json::json!(value));
    }

    if let Ok(list) = object.cast::<PyList>() {
        let mut values = Vec::new();
        for item in list {
            values.push(json_from_py(&item)?);
        }
        return Ok(JsonValue::Array(values));
    }

    if let Ok(tuple) = object.cast::<PyTuple>() {
        let mut values = Vec::new();
        for item in tuple {
            values.push(json_from_py(&item)?);
        }
        return Ok(JsonValue::Array(values));
    }

    if let Ok(dict) = object.cast::<PyDict>() {
        let mut values = JsonMap::new();
        for (key, value) in dict {
            let key = key
                .extract::<String>()
                .map_err(|_| BindingError::AttributeKey)?;
            values.insert(key, json_from_py(&value)?);
        }
        return Ok(JsonValue::Object(values));
    }

    Err(BindingError::attribute_value("<json>").into())
}

fn set_attribute(
    attributes: &mut AttributeMap,
    key: &str,
    value: &Bound<'_, PyAny>,
    default_space: usize,
) -> PyResult<()> {
    match key {
        "image_base" | ATTRIBUTE_IMAGE_BASE => {
            attributes.set_attr(
                ATTRIBUTE_IMAGE_BASE,
                RawAddress::new(value.extract::<u64>()?),
            );
        }
        "address_space" | ATTRIBUTE_ADDRESS_SPACE => {
            attributes.set_attr(ATTRIBUTE_ADDRESS_SPACE, address_space_id(value.extract()?)?);
        }
        "entry_point" | ATTRIBUTE_ENTRY_POINT => {
            attributes.set_attr(
                ATTRIBUTE_ENTRY_POINT,
                address_from_any(value, default_space)?,
            );
        }
        "project_path" | ATTRIBUTE_PROJECT_PATH => {
            attributes.set_attr(ATTRIBUTE_PROJECT_PATH, value.extract::<PathBuf>()?);
        }
        "input_path" | "file_path" | ATTRIBUTE_INPUT_PATH => {
            attributes.set_attr(ATTRIBUTE_INPUT_PATH, value.extract::<PathBuf>()?);
        }
        "override_segment_permissions" | ATTRIBUTE_OVERRIDE_SEGMENT_PERMISSIONS => {
            attributes.set_attr(
                ATTRIBUTE_OVERRIDE_SEGMENT_PERMISSIONS,
                value.extract::<bool>()?,
            );
        }
        _ => {
            attributes.set_attr(key, json_from_py(value)?);
        }
    }

    Ok(())
}

pub(crate) fn attribute_map_from_py(object: Option<&Bound<'_, PyAny>>) -> PyResult<AttributeMap> {
    let mut attributes = AttributeMap::new();
    let Some(object) = object else {
        return Ok(attributes);
    };

    if object.is_none() {
        return Ok(attributes);
    }

    let dict = object
        .cast::<PyDict>()
        .map_err(|_| BindingError::AttributesNotDict)?;

    let mut default_space = 0usize;
    for (key, value) in dict {
        let key = key
            .extract::<String>()
            .map_err(|_| BindingError::AttributeKey)?;
        if matches!(key.as_str(), "address_space" | ATTRIBUTE_ADDRESS_SPACE) {
            default_space = value.extract()?;
            break;
        }
    }

    for (key, value) in dict {
        let key = key
            .extract::<String>()
            .map_err(|_| BindingError::AttributeKey)?;
        set_attribute(&mut attributes, &key, &value, default_space)?;
    }

    Ok(attributes)
}
