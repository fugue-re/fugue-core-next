use thiserror::Error;

use crate::analysis::control::Cancelled;
use crate::il::common::IlError;
use crate::il::pcode::AddressAnnotationRole;
use crate::lifter::LifterError;
use crate::storage::SegmentStorageError;

#[derive(Debug, Error)]
pub enum PCodeError {
    #[error(transparent)]
    Common(#[from] IlError),
    #[error("duplicate address annotation for ordinal {ordinal} role {role:?}")]
    DuplicateAnnotation {
        ordinal: u32,
        role: AddressAnnotationRole,
    },
    #[error(
        "operation at ordinal {ordinal} has invalid argument count {found}, expected {expected}"
    )]
    InvalidArgumentCount {
        ordinal: u32,
        expected: u8,
        found: u8,
    },
    #[error("operation at ordinal {ordinal} targets non-semantic PCode position {position}")]
    InvalidLocalTarget { ordinal: u32, position: u16 },
    #[error("operation at ordinal {ordinal} is not a semantic PCode opcode")]
    InvalidOpcode { ordinal: u32 },
    #[error(transparent)]
    Lifter(#[from] LifterError),
    #[error("ARG operation at ordinal {ordinal} is not attached to a user operation")]
    MisplacedArg { ordinal: u32 },
    #[error("missing address annotation for ordinal {ordinal} role {role:?}")]
    MissingAnnotation {
        ordinal: u32,
        role: AddressAnnotationRole,
    },
    #[error("user operation at ordinal {ordinal} is missing {missing} spilled arguments")]
    MissingArg { ordinal: u32, missing: u8 },
    #[error("out-of-order address annotation for ordinal {ordinal} role {role:?}")]
    OutOfOrderAnnotation {
        ordinal: u32,
        role: AddressAnnotationRole,
    },
    #[error(transparent)]
    SegmentStorage(#[from] SegmentStorageError),
    #[error("unused address annotation for ordinal {ordinal} role {role:?}")]
    UnusedAnnotation {
        ordinal: u32,
        role: AddressAnnotationRole,
    },
    #[error("address annotation for ordinal {ordinal} has role {found:?}, expected {expected:?}")]
    WrongAnnotationRole {
        ordinal: u32,
        expected: AddressAnnotationRole,
        found: AddressAnnotationRole,
    },
}

impl PCodeError {
    pub const fn duplicate_annotation(ordinal: u32, role: AddressAnnotationRole) -> Self {
        Self::DuplicateAnnotation { ordinal, role }
    }

    pub const fn invalid_argument_count(ordinal: u32, expected: u8, found: u8) -> Self {
        Self::InvalidArgumentCount {
            ordinal,
            expected,
            found,
        }
    }

    pub const fn invalid_opcode(ordinal: u32) -> Self {
        Self::InvalidOpcode { ordinal }
    }

    pub const fn invalid_local_target(ordinal: u32, position: u16) -> Self {
        Self::InvalidLocalTarget { ordinal, position }
    }

    pub const fn misplaced_arg(ordinal: u32) -> Self {
        Self::MisplacedArg { ordinal }
    }

    pub const fn missing_annotation(ordinal: u32, role: AddressAnnotationRole) -> Self {
        Self::MissingAnnotation { ordinal, role }
    }

    pub const fn missing_arg(ordinal: u32, missing: u8) -> Self {
        Self::MissingArg { ordinal, missing }
    }

    pub const fn out_of_order_annotation(ordinal: u32, role: AddressAnnotationRole) -> Self {
        Self::OutOfOrderAnnotation { ordinal, role }
    }

    pub const fn unused_annotation(ordinal: u32, role: AddressAnnotationRole) -> Self {
        Self::UnusedAnnotation { ordinal, role }
    }

    pub const fn wrong_annotation_role(
        ordinal: u32,
        expected: AddressAnnotationRole,
        found: AddressAnnotationRole,
    ) -> Self {
        Self::WrongAnnotationRole {
            ordinal,
            expected,
            found,
        }
    }
}

impl From<Cancelled> for PCodeError {
    fn from(cancelled: Cancelled) -> Self {
        Self::Common(IlError::from(cancelled))
    }
}
