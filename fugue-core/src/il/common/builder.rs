use crate::il::common::IlError;

pub trait BuildCancellation {
    fn is_cancelled(&self) -> bool;
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct BuildStatus {
    cancelled: bool,
}

impl BuildStatus {
    pub const fn new() -> Self {
        Self { cancelled: false }
    }

    pub const fn cancelled() -> Self {
        Self { cancelled: true }
    }

    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn check(&self) -> Result<(), IlError> {
        if self.cancelled {
            Err(IlError::cancelled())
        } else {
            Ok(())
        }
    }
}

impl BuildCancellation for BuildStatus {
    fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

pub trait Finish {
    type Output;

    fn finish(self, status: &(impl BuildCancellation + ?Sized)) -> Result<Self::Output, IlError>;
}
