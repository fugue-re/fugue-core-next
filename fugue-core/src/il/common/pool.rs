use crate::il::common::IlError;

#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct IlIndexRange {
    start: u32,
    end: u32,
}

impl IlIndexRange {
    pub const EMPTY: Self = Self { start: 0, end: 0 };

    pub(crate) fn new(start: usize, end: usize) -> Result<Self, IlError> {
        if start > end {
            return Err(IlError::reversed_range(
                u32::try_from(start).unwrap_or(u32::MAX),
                u32::try_from(end).unwrap_or(u32::MAX),
            ));
        }

        let start = u32::try_from(start).map_err(|_| IlError::integer_overflow("range start"))?;
        let end = u32::try_from(end).map_err(|_| IlError::integer_overflow("range end"))?;

        Ok(Self { start, end })
    }

    pub const fn start(&self) -> usize {
        self.start as usize
    }

    pub const fn end(&self) -> usize {
        self.end as usize
    }

    pub const fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub const fn contains_index(&self, index: usize) -> bool {
        self.start() <= index && index < self.end()
    }

    pub fn slice<'a, T>(&self, values: &'a [T]) -> &'a [T] {
        &values[self.start()..self.end()]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IlPool<T> {
    values: Vec<T>,
}

impl<T> IlPool<T> {
    pub(crate) fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub(crate) fn append(
        &mut self,
        values: impl IntoIterator<Item = T>,
    ) -> Result<IlIndexRange, IlError> {
        let start = self.values.len();
        self.values.extend(values);
        let end = self.values.len();

        IlIndexRange::new(start, end)
    }

    pub(crate) fn into_values(self) -> Vec<T> {
        self.values
    }

    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn index_range_stays_compact() {
        assert_eq!(size_of::<IlIndexRange>(), 8);
    }

    #[test]
    fn range_rejects_reversed_bounds() {
        assert!(matches!(
            IlIndexRange::new(3, 2),
            Err(IlError::ReversedRange { .. })
        ));
    }
}
