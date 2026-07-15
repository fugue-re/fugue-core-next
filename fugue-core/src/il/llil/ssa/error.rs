use thiserror::Error;

use crate::il::common::IlError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SsaError {
    #[error(transparent)]
    Common(#[from] IlError),
    #[error("definition does not dominate use")]
    NonDominatingUse,
    #[error("block argument count mismatch")]
    BlockArgumentCount,
    #[error("memory version cycle")]
    MemoryVersionCycle,
}
