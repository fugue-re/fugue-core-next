use crate::il::common::{BuildCancellation, IlError, IrArtefact};

#[derive(Debug, Default)]
pub struct Scratch {
    bytes_cap: usize,
    bytes: Vec<u8>,
}

impl Scratch {
    pub fn new(bytes_cap: usize) -> Self {
        Self {
            bytes_cap,
            bytes: Vec::new(),
        }
    }

    pub fn bytes(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    pub fn bytes_with_len(&mut self, len: usize) -> &mut [u8] {
        self.bytes.clear();
        self.bytes.resize(len, 0);
        &mut self.bytes
    }

    pub const fn bytes_cap(&self) -> usize {
        self.bytes_cap
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    pub fn trim(&mut self) {
        if self.bytes.capacity() > self.bytes_cap {
            self.bytes.shrink_to(self.bytes_cap);
        }
    }

    pub fn reset(&mut self) {
        self.clear();
        self.trim();
    }
}

pub struct TransformContext<'a> {
    cancellation: &'a dyn BuildCancellation,
    scratch: &'a mut Scratch,
}

impl<'a> TransformContext<'a> {
    pub fn new(cancellation: &'a dyn BuildCancellation, scratch: &'a mut Scratch) -> Self {
        Self {
            cancellation,
            scratch,
        }
    }

    pub fn check_cancelled(&self) -> Result<(), IlError> {
        if self.cancellation.is_cancelled() {
            Err(IlError::cancelled())
        } else {
            Ok(())
        }
    }

    pub fn scratch(&mut self) -> &mut Scratch {
        self.scratch
    }

    pub fn cancellation(&self) -> &dyn BuildCancellation {
        self.cancellation
    }

    pub fn finish<T>(&mut self, result: Result<T, IlError>) -> Result<T, IlError> {
        self.scratch.reset();
        result
    }
}

pub trait Transform<Source, Destination>
where
    Source: IrArtefact,
    Destination: IrArtefact,
{
    fn transform(
        &mut self,
        source: &Source,
        context: &mut TransformContext<'_>,
    ) -> Result<Destination, IlError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::BuildStatus;

    #[test]
    fn transform_context_reports_cancellation() {
        let status = BuildStatus::cancelled();
        let mut scratch = Scratch::new(16);
        let context = TransformContext::new(&status, &mut scratch);

        assert!(matches!(context.check_cancelled(), Err(IlError::Cancelled)));
    }

    #[test]
    fn scratch_bytes_with_len_reuses_buffer_as_slice() {
        let mut scratch = Scratch::new(16);

        scratch.bytes_with_len(4).copy_from_slice(&[1, 2, 3, 4]);
        let capacity = scratch.bytes().capacity();

        assert_eq!(scratch.bytes().as_slice(), [1, 2, 3, 4]);

        scratch.bytes_with_len(2);

        assert_eq!(scratch.bytes().as_slice(), [0, 0]);
        assert_eq!(scratch.bytes().capacity(), capacity);
    }

    #[test]
    fn transform_finish_resets_scratch_on_success() {
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(4);
        scratch.bytes().resize(64, 0);
        let mut context = TransformContext::new(&status, &mut scratch);

        assert_eq!(context.finish(Ok(7)).unwrap(), 7);

        assert_eq!(scratch.bytes().len(), 0);
        assert!(scratch.bytes().capacity() <= scratch.bytes_cap());
    }

    #[test]
    fn transform_finish_resets_scratch_on_error() {
        let status = BuildStatus::new();
        let mut scratch = Scratch::new(4);
        scratch.bytes().resize(64, 0);
        let mut context = TransformContext::new(&status, &mut scratch);

        assert!(matches!(
            context.finish::<()>(Err(IlError::cancelled())),
            Err(IlError::Cancelled)
        ));

        assert_eq!(scratch.bytes().len(), 0);
        assert!(scratch.bytes().capacity() <= scratch.bytes_cap());
    }
}
