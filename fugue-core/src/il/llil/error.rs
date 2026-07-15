use thiserror::Error;

use crate::il::common::IlError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LlilError {
    #[error(transparent)]
    Common(#[from] IlError),
    #[error(
        "register slice {register} offset {offset} width {width} exceeds root width {root_width}"
    )]
    InvalidRegisterSlice {
        register: u32,
        offset: u32,
        width: u32,
        root_width: u32,
    },
    #[error("raw lifter space handle cannot be represented in LLIL")]
    RawLifterSpace,
}

impl LlilError {
    pub const fn invalid_register_slice(
        register: u32,
        offset: u32,
        width: u32,
        root_width: u32,
    ) -> Self {
        Self::InvalidRegisterSlice {
            register,
            offset,
            width,
            root_width,
        }
    }
}
