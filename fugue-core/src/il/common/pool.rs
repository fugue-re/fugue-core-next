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

    pub(crate) fn checked_slice<'a, T>(&self, values: &'a [T]) -> Result<&'a [T], IlError> {
        self.verify_bounds(values.len())?;
        Ok(self.slice(values))
    }

    pub fn slice<'a, T>(&self, values: &'a [T]) -> &'a [T] {
        &values[self.start()..self.end()]
    }

    pub(crate) fn verify_bounds(&self, len: usize) -> Result<(), IlError> {
        if self.start() > self.end() {
            return Err(IlError::reversed_range(self.start, self.end));
        }

        if self.end() > len {
            return Err(IlError::range_out_of_bounds(self.end, len));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IlIndexMapper {
    indices: Vec<usize>,
}

impl IlIndexMapper {
    pub(crate) fn new(indices: Vec<usize>) -> Self {
        assert!(!indices.is_empty(), "index map has a terminal boundary");
        assert!(
            indices.windows(2).all(|pair| pair[0] <= pair[1]),
            "index map preserves boundary order"
        );
        Self { indices }
    }

    pub(crate) fn from_kept(len: usize, mut kept: impl FnMut(usize) -> bool) -> Self {
        let mut indices = Vec::with_capacity(len.checked_add(1).expect("index count fits usize"));
        indices.push(0usize);
        for index in 0..len {
            let next = indices[index]
                .checked_add(usize::from(kept(index)))
                .expect("compacted index fits usize");
            indices.push(next);
        }
        Self { indices }
    }

    pub(crate) fn map_index(&self, index: usize) -> usize {
        self.indices[index]
    }

    pub(crate) fn map_range(&self, range: IlIndexRange) -> IlIndexRange {
        IlIndexRange::new(self.map_index(range.start()), self.map_index(range.end()))
            .expect("index remapping preserves range order")
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IlCsr<T> {
    offsets: Vec<u32>,
    values: Vec<T>,
}

impl<T> Default for IlCsr<T> {
    fn default() -> Self {
        Self {
            offsets: vec![0],
            values: Vec::new(),
        }
    }
}

impl<T> IlCsr<T> {
    pub(crate) fn from_rows<R, I>(rows: R) -> Self
    where
        R: IntoIterator<Item = I>,
        I: IntoIterator<Item = T>,
    {
        let mut offsets = vec![0];
        let mut values = Vec::new();

        for row in rows {
            values.extend(row);
            offsets.push(u32::try_from(values.len()).expect("CSR entry count fits u32"));
        }

        Self { offsets, values }
    }

    pub(crate) fn row(&self, index: usize) -> &[T] {
        let Some(start) = self.offsets.get(index).copied() else {
            return &[];
        };
        let end = self.offsets.get(index + 1).copied().unwrap_or(start);

        &self.values[start as usize..end as usize]
    }
}

impl<T: Copy> IlCsr<T> {
    pub(crate) fn from_entries<I>(row_count: usize, entries: I) -> Self
    where
        I: Clone + Iterator<Item = (usize, T)>,
    {
        let offset_count = row_count.checked_add(1).expect("CSR row count fits usize");
        let mut offsets = vec![0u32; offset_count];

        let Some((_, fill)) = entries.clone().next() else {
            return Self {
                offsets,
                values: Vec::new(),
            };
        };

        for (row, _) in entries.clone() {
            let offset = row.checked_add(1).expect("CSR row index fits usize");
            let count = offsets
                .get_mut(offset)
                .expect("CSR entry row is within the row count");
            *count = count.checked_add(1).expect("CSR row length fits u32");
        }

        for index in 1..offsets.len() {
            offsets[index] = offsets[index]
                .checked_add(offsets[index - 1])
                .expect("CSR entry count fits u32");
        }

        let mut cursor = offsets.clone();
        let value_count = offsets.last().copied().unwrap_or(0) as usize;
        let mut values = vec![fill; value_count];

        for (row, value) in entries {
            let index = cursor[row] as usize;
            values[index] = value;
            cursor[row] = cursor[row].checked_add(1).expect("CSR row cursor fits u32");
        }

        Self { offsets, values }
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

    #[test]
    fn range_verifier_rejects_out_of_bounds_end() {
        let range = IlIndexRange::new(0, 2).unwrap();

        assert!(matches!(
            range.verify_bounds(1),
            Err(IlError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn index_mapper_maps_source_boundaries() {
        let mapper = IlIndexMapper::new(vec![0, 0, 1, 3]);

        assert_eq!(mapper.map_index(1), 0);
        assert_eq!(
            mapper.map_range(IlIndexRange::new(1, 3).unwrap()),
            IlIndexRange::new(0, 3).unwrap()
        );
    }

    #[test]
    fn csr_preserves_rows_and_entry_order() {
        let csr = IlCsr::from_entries(4, [(2, 4), (0, 1), (2, 5), (0, 2)].into_iter());

        assert_eq!(csr.row(0), &[1, 2]);
        assert!(csr.row(1).is_empty());
        assert_eq!(csr.row(2), &[4, 5]);
        assert!(csr.row(3).is_empty());
        assert!(csr.row(4).is_empty());
    }

    #[test]
    fn csr_builds_from_grouped_rows() {
        let csr = IlCsr::from_rows([vec![1, 2], Vec::new(), vec![3]]);

        assert_eq!(csr.row(0), &[1, 2]);
        assert!(csr.row(1).is_empty());
        assert_eq!(csr.row(2), &[3]);
    }
}
