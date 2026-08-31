use smallvec::SmallVec;

use crate::lifter::ContextSet;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ExternalThunkTemplate {
    bytes: SmallVec<[u8; 16]>,
    context: ContextSet,
}

impl<T> From<T> for ExternalThunkTemplate
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl ExternalThunkTemplate {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self::new_with(bytes, ContextSet::default())
    }

    pub fn new_with(bytes: impl AsRef<[u8]>, context: ContextSet) -> Self {
        Self {
            bytes: SmallVec::from_slice(bytes.as_ref()),
            context,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn context(&self) -> &ContextSet {
        &self.context
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
