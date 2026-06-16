#![allow(unknown_lints, unnecessary_qualified_type_paths)]

mod address;
mod attributes;
mod binary;
mod convert;
mod errors;
mod lifter;
mod segments;

use pyo3::prelude::*;
use pyo3::types::PyModule;

#[pymodule]
fn fugue(module: &Bound<'_, PyModule>) -> PyResult<()> {
    address::add_classes(module)?;
    binary::add_classes(module)?;
    errors::add_errors(module)?;
    lifter::add_classes(module)?;
    segments::add_classes(module)?;

    Ok(())
}
