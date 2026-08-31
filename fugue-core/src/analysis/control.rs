use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

#[derive(Debug, Clone, Copy, Error)]
#[error("analysis cancelled")]
pub struct Cancelled;

#[derive(Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationInner>,
}

#[derive(Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    parent: Option<CancellationToken>,
}

impl CancellationToken {
    pub fn child(&self) -> Self {
        Self {
            inner: Arc::new(CancellationInner {
                cancelled: AtomicBool::new(false),
                parent: Some(self.clone()),
            }),
        }
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
    }

    pub fn clear(&self) {
        self.inner.cancelled.store(false, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
            || self
                .inner
                .parent
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
    }

    pub fn check(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }
}
