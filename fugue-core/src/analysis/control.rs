use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::RwLock;
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

#[derive(Clone, Default)]
pub struct Progress {
    inner: Arc<ProgressInner>,
}

#[derive(Default)]
struct ProgressInner {
    done: AtomicU64,
    total: AtomicU64,
    message: RwLock<Option<String>>,
}

impl Progress {
    pub fn done(&self) -> u64 {
        self.inner.done.load(Ordering::Acquire)
    }

    pub fn total(&self) -> u64 {
        self.inner.total.load(Ordering::Acquire)
    }

    pub fn message(&self) -> Option<String> {
        self.inner.message.read().clone()
    }

    pub fn reset(&self) {
        self.inner.done.store(0, Ordering::Release);
        self.inner.total.store(0, Ordering::Release);
        self.inner.message.write().take();
    }

    pub fn set_total(&self, total: u64) {
        self.inner.total.store(total, Ordering::Release);
    }

    pub fn set_message(&self, message: impl Into<String>) {
        *self.inner.message.write() = Some(message.into());
    }

    pub fn clear_message(&self) {
        self.inner.message.write().take();
    }

    pub fn advance(&self, amount: u64) {
        self.inner.done.fetch_add(amount, Ordering::AcqRel);
    }
}
