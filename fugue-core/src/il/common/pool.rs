use super::span::{IlParentSpan, IlSourceSpan};
use crate::il::common::IlError;

fn merge_parent_spans(mut spans: Vec<IlParentSpan>) -> Result<Vec<IlParentSpan>, IlError> {
    spans.sort_unstable_by_key(|span| span.destination().start());
    let mut merged = Vec::<IlParentSpan>::with_capacity(spans.len());
    for span in spans {
        if let Some(previous) = merged.last_mut()
            && previous.try_merge(span)?
        {
            continue;
        }
        merged.push(span);
    }
    Ok(merged)
}

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

    pub fn new(start: usize, end: usize) -> Result<Self, IlError> {
        if start > end {
            return Err(IlError::reversed_range(start, end));
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

    pub fn checked_slice<'a, T>(&self, values: &'a [T]) -> Result<&'a [T], IlError> {
        self.verify_bounds(values.len())?;
        Ok(self.slice(values))
    }

    pub fn slice<'a, T>(&self, values: &'a [T]) -> &'a [T] {
        &values[self.start()..self.end()]
    }

    pub fn verify_bounds(&self, len: usize) -> Result<(), IlError> {
        if self.start() > self.end() {
            return Err(IlError::reversed_range(self.start(), self.end()));
        }

        if self.end() > len {
            return Err(IlError::range_out_of_bounds(self.end(), len));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IlIndexMapper {
    indices: Vec<usize>,
}

impl IlIndexMapper {
    pub fn new(indices: Vec<usize>) -> Result<Self, IlError> {
        if indices.is_empty() {
            return Err(IlError::missing_index_boundary());
        }

        if let Some(pair) = indices.windows(2).find(|pair| pair[0] > pair[1]) {
            return Err(IlError::reversed_range(pair[0], pair[1]));
        }

        Ok(Self { indices })
    }

    pub fn from_kept(len: usize, mut kept: impl FnMut(usize) -> bool) -> Self {
        let mut indices = Vec::with_capacity(len.saturating_add(1));
        indices.push(0usize);
        for index in 0..len {
            let next = indices[index] + usize::from(kept(index));
            indices.push(next);
        }
        Self { indices }
    }

    pub fn source_len(&self) -> usize {
        self.indices.len() - 1
    }

    pub fn checked_map_index(&self, index: usize) -> Option<usize> {
        self.indices.get(index).copied()
    }

    pub fn map_index(&self, index: usize) -> usize {
        self.checked_map_index(index)
            .expect("index is within the mapper source domain")
    }

    pub fn checked_map_range(&self, range: IlIndexRange) -> Result<IlIndexRange, IlError> {
        range.verify_bounds(self.source_len())?;
        IlIndexRange::new(self.indices[range.start()], self.indices[range.end()])
    }

    pub fn map_range(&self, range: IlIndexRange) -> IlIndexRange {
        self.checked_map_range(range)
            .expect("range is within the mapper source domain")
    }

    pub fn parent_spans(&self) -> Result<Vec<IlParentSpan>, IlError> {
        let mut spans = Vec::with_capacity(self.source_len());
        for source in 0..self.source_len() {
            let source = IlIndexRange::new(source, source + 1)?;
            let destination = self.map_range(source);
            if !destination.is_empty() {
                spans.push(IlParentSpan::new(destination, source));
            }
        }
        merge_parent_spans(spans)
    }

    pub fn remap_source_spans(
        &self,
        source_spans: &[IlSourceSpan],
    ) -> Result<Vec<IlSourceSpan>, IlError> {
        let mut spans = Vec::with_capacity(source_spans.len());
        for span in source_spans {
            let destination = self.checked_map_range(span.destination())?;
            if destination.is_empty() {
                continue;
            }
            spans.push(IlSourceSpan::new(
                destination,
                span.address(),
                span.first_source_index(),
                span.source_count(),
            ));
        }
        Ok(spans)
    }

    pub fn remap_parent_spans(
        &self,
        parent_spans: &[IlParentSpan],
    ) -> Result<Vec<IlParentSpan>, IlError> {
        let mut spans = Vec::with_capacity(parent_spans.len());
        for span in parent_spans {
            let destination = self.checked_map_range(span.destination())?;
            if !destination.is_empty() {
                spans.push(IlParentSpan::new(destination, span.source()));
            }
        }
        Ok(spans)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlIndexRangeMap {
    ranges: Vec<IlIndexRange>,
}

impl IlIndexRangeMap {
    pub(crate) fn unmapped(source_len: usize) -> Self {
        Self {
            ranges: vec![IlIndexRange::EMPTY; source_len],
        }
    }

    pub fn new(ranges: Vec<IlIndexRange>) -> Self {
        Self { ranges }
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn range_for(&self, index: usize) -> Option<IlIndexRange> {
        self.ranges.get(index).copied()
    }

    pub fn ranges(&self) -> &[IlIndexRange] {
        &self.ranges
    }

    pub(crate) fn set_range(&mut self, index: usize, range: IlIndexRange) -> Result<(), IlError> {
        if index >= self.ranges.len() {
            return Err(IlError::range_out_of_bounds(index, self.ranges.len()));
        }

        self.ranges[index] = range;
        Ok(())
    }

    pub fn remap_into(
        &self,
        source: IlIndexRange,
        destinations: &mut Vec<IlIndexRange>,
    ) -> Result<(), IlError> {
        source.verify_bounds(self.ranges.len())?;
        destinations.clear();
        destinations.extend(
            source
                .slice(&self.ranges)
                .iter()
                .copied()
                .filter(|range| !range.is_empty()),
        );
        destinations.sort_unstable_by_key(IlIndexRange::start);

        let mut retained = 0usize;
        for index in 0..destinations.len() {
            let destination = destinations[index];
            if retained == 0 {
                destinations[retained] = destination;
                retained += 1;
                continue;
            }

            let previous = &mut destinations[retained - 1];
            if destination.start() < previous.end() {
                return Err(IlError::overlapping_ranges(
                    destination.start(),
                    previous.end(),
                ));
            }
            if previous.end() == destination.start() {
                *previous = IlIndexRange::new(previous.start(), destination.end())?;
            } else {
                destinations[retained] = destination;
                retained += 1;
            }
        }
        destinations.truncate(retained);

        Ok(())
    }

    pub fn remap_source_spans(
        &self,
        source_spans: &[IlSourceSpan],
    ) -> Result<Vec<IlSourceSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut spans = Vec::new();
        for span in source_spans {
            self.remap_into(span.destination(), &mut destinations)?;
            for &destination in &destinations {
                spans.push(IlSourceSpan::new(
                    destination,
                    span.address(),
                    span.first_source_index(),
                    span.source_count(),
                ));
            }
        }

        spans.sort_unstable_by_key(|span| span.destination().start());
        let mut merged = Vec::<IlSourceSpan>::with_capacity(spans.len());
        for span in spans {
            if let Some(previous) = merged.last_mut()
                && previous.try_merge(span)?
            {
                continue;
            }
            merged.push(span);
        }

        Ok(merged)
    }

    pub fn parent_spans(&self) -> Result<Vec<IlParentSpan>, IlError> {
        let mut spans = Vec::with_capacity(self.ranges.len());
        for (index, &destination) in self.ranges.iter().enumerate() {
            if destination.is_empty() {
                continue;
            }
            let source = IlIndexRange::new(index, index + 1)?;
            spans.push(IlParentSpan::new(destination, source));
        }
        merge_parent_spans(spans)
    }

    pub fn remap_parent_spans(
        &self,
        parent_spans: &[IlParentSpan],
    ) -> Result<Vec<IlParentSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut spans = Vec::new();
        for span in parent_spans {
            self.remap_into(span.destination(), &mut destinations)?;
            for &destination in &destinations {
                spans.push(IlParentSpan::new(destination, span.source()));
            }
        }
        spans.sort_unstable_by_key(|span| span.destination().start());
        Ok(spans)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IlPool<T> {
    values: Vec<T>,
}

impl<T> IlPool<T> {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn append(&mut self, values: impl IntoIterator<Item = T>) -> Result<IlIndexRange, IlError> {
        let start = self.values.len();
        self.values.extend(values);
        let end = self.values.len();

        IlIndexRange::new(start, end)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn values(&self) -> &[T] {
        &self.values
    }

    pub fn into_values(self) -> Vec<T> {
        self.values
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IlCsr<T> {
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
    pub fn try_from_rows<R, I>(rows: R) -> Result<Self, IlError>
    where
        R: IntoIterator<Item = I>,
        I: IntoIterator<Item = T>,
    {
        let mut offsets = vec![0];
        let mut values = Vec::new();

        for row in rows {
            values.extend(row);
            offsets.push(
                u32::try_from(values.len())
                    .map_err(|_| IlError::integer_overflow("CSR entry count"))?,
            );
        }

        Ok(Self { offsets, values })
    }

    pub(crate) fn from_rows<R, I>(rows: R) -> Self
    where
        R: IntoIterator<Item = I>,
        I: IntoIterator<Item = T>,
    {
        Self::try_from_rows(rows).expect("internal CSR entry count fits u32")
    }

    pub fn len(&self) -> usize {
        self.offsets.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn checked_row(&self, index: usize) -> Option<&[T]> {
        let start = *self.offsets.get(index)?;
        let end = *self.offsets.get(index + 1)?;

        Some(&self.values[start as usize..end as usize])
    }

    pub fn row(&self, index: usize) -> &[T] {
        let start = self.offsets[index];
        let end = self.offsets[index + 1];

        &self.values[start as usize..end as usize]
    }
}

impl<T: Copy> IlCsr<T> {
    pub fn try_from_entries<I>(row_count: usize, entries: I) -> Result<Self, IlError>
    where
        I: Clone + Iterator<Item = (usize, T)>,
    {
        let offset_count = row_count
            .checked_add(1)
            .ok_or_else(|| IlError::integer_overflow("CSR row count"))?;
        let mut offsets = vec![0u32; offset_count];

        let Some((_, fill)) = entries.clone().next() else {
            return Ok(Self {
                offsets,
                values: Vec::new(),
            });
        };

        for (row, _) in entries.clone() {
            let offset = row
                .checked_add(1)
                .ok_or_else(|| IlError::integer_overflow("CSR row index"))?;
            let offset_count = offsets.len();
            let count = offsets
                .get_mut(offset)
                .ok_or_else(|| IlError::range_out_of_bounds(offset, offset_count))?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| IlError::integer_overflow("CSR row length"))?;
        }

        for index in 1..offsets.len() {
            offsets[index] = offsets[index]
                .checked_add(offsets[index - 1])
                .ok_or_else(|| IlError::integer_overflow("CSR entry count"))?;
        }

        let mut cursor = offsets.clone();
        let value_count = offsets.last().copied().unwrap_or(0) as usize;
        let mut values = vec![fill; value_count];

        for (row, value) in entries {
            let index = cursor[row] as usize;
            values[index] = value;
            cursor[row] += 1;
        }

        Ok(Self { offsets, values })
    }

    pub(crate) fn from_entries<I>(row_count: usize, entries: I) -> Self
    where
        I: Clone + Iterator<Item = (usize, T)>,
    {
        Self::try_from_entries(row_count, entries)
            .expect("internal CSR entries use valid rows and fit u32")
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;
    use crate::ir::Address;

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
        let mapper = IlIndexMapper::new(vec![0, 0, 1, 3]).unwrap();

        assert_eq!(mapper.source_len(), 3);
        assert_eq!(mapper.map_index(1), 0);
        assert_eq!(
            mapper.map_range(IlIndexRange::new(1, 3).unwrap()),
            IlIndexRange::new(0, 3).unwrap()
        );
        assert_eq!(mapper.checked_map_index(4), None);
        assert_eq!(
            mapper.checked_map_range(IlIndexRange::new(2, 4).unwrap()),
            Err(IlError::RangeOutOfBounds { end: 4, len: 3 })
        );
    }

    #[test]
    fn index_mapper_remaps_exact_provenance_spans() {
        let mapper = IlIndexMapper::new(vec![0, 1, 1, 2]).unwrap();
        let address = Address::from(0x1000u64);
        let source_spans = [
            IlSourceSpan::try_new(IlIndexRange::new(0, 1).unwrap(), address, 0, 1).unwrap(),
            IlSourceSpan::try_new(IlIndexRange::new(1, 2).unwrap(), address, 1, 1).unwrap(),
            IlSourceSpan::try_new(IlIndexRange::new(2, 3).unwrap(), address, 2, 1).unwrap(),
        ];
        let parent_spans = [
            IlParentSpan::new(
                IlIndexRange::new(0, 1).unwrap(),
                IlIndexRange::new(4, 5).unwrap(),
            ),
            IlParentSpan::new(
                IlIndexRange::new(1, 2).unwrap(),
                IlIndexRange::new(5, 6).unwrap(),
            ),
            IlParentSpan::new(
                IlIndexRange::new(2, 3).unwrap(),
                IlIndexRange::new(6, 7).unwrap(),
            ),
        ];

        let source_spans = mapper.remap_source_spans(&source_spans).unwrap();
        let parent_spans = mapper.remap_parent_spans(&parent_spans).unwrap();

        assert_eq!(source_spans.len(), 2);
        assert_eq!(
            source_spans[0].destination(),
            IlIndexRange::new(0, 1).unwrap()
        );
        assert_eq!(source_spans[0].first_source_index(), 0);
        assert_eq!(
            source_spans[1].destination(),
            IlIndexRange::new(1, 2).unwrap()
        );
        assert_eq!(source_spans[1].first_source_index(), 2);
        assert_eq!(parent_spans.len(), 2);
        assert_eq!(
            parent_spans[0].destination(),
            IlIndexRange::new(0, 1).unwrap()
        );
        assert_eq!(parent_spans[0].source(), IlIndexRange::new(4, 5).unwrap());
        assert_eq!(
            parent_spans[1].destination(),
            IlIndexRange::new(1, 2).unwrap()
        );
        assert_eq!(parent_spans[1].source(), IlIndexRange::new(6, 7).unwrap());

        let collapsed =
            IlSourceSpan::try_new(IlIndexRange::new(0, 3).unwrap(), address, 0, 3).unwrap();
        assert_eq!(
            mapper.remap_source_spans(&[collapsed]).unwrap()[0].destination(),
            IlIndexRange::new(0, 2).unwrap()
        );
    }

    #[test]
    fn reversed_range_reports_the_supplied_collection_positions() {
        assert_eq!(
            IlIndexRange::new(usize::MAX, 0),
            Err(IlError::ReversedRange {
                start: usize::MAX,
                end: 0,
            })
        );
    }

    #[test]
    fn csr_preserves_rows_and_entry_order() {
        let csr = IlCsr::try_from_entries(4, [(2, 4), (0, 1), (2, 5), (0, 2)].into_iter()).unwrap();

        assert_eq!(csr.len(), 4);
        assert!(!csr.is_empty());
        assert_eq!(csr.row(0), &[1, 2]);
        assert!(csr.row(1).is_empty());
        assert_eq!(csr.row(2), &[4, 5]);
        assert!(csr.row(3).is_empty());
        assert_eq!(csr.checked_row(3), Some(&[][..]));
        assert_eq!(csr.checked_row(4), None);
    }

    #[test]
    fn csr_builds_from_grouped_rows() {
        let csr = IlCsr::try_from_rows([vec![1, 2], Vec::new(), vec![3]]).unwrap();

        assert_eq!(csr.row(0), &[1, 2]);
        assert!(csr.row(1).is_empty());
        assert_eq!(csr.row(2), &[3]);
    }

    #[test]
    fn empty_csr_has_no_rows() {
        let csr = IlCsr::<u32>::default();

        assert_eq!(csr.len(), 0);
        assert!(csr.is_empty());
        assert_eq!(csr.checked_row(0), None);
    }

    #[test]
    fn range_map_coalesces_adjacent_destinations() {
        let map = IlIndexRangeMap::new(vec![
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(2, 2).unwrap(),
            IlIndexRange::new(2, 4).unwrap(),
            IlIndexRange::new(6, 7).unwrap(),
        ]);
        let mut destinations = Vec::new();

        map.remap_into(IlIndexRange::new(0, 4).unwrap(), &mut destinations)
            .unwrap();

        assert_eq!(
            destinations,
            vec![
                IlIndexRange::new(0, 4).unwrap(),
                IlIndexRange::new(6, 7).unwrap()
            ]
        );
    }

    #[test]
    fn range_map_orders_destinations_without_changing_source_mapping() {
        let map = IlIndexRangeMap::new(vec![
            IlIndexRange::new(2, 4).unwrap(),
            IlIndexRange::EMPTY,
            IlIndexRange::new(0, 2).unwrap(),
        ]);
        let mut destinations = Vec::new();

        map.remap_into(IlIndexRange::new(0, 3).unwrap(), &mut destinations)
            .unwrap();

        assert_eq!(destinations, vec![IlIndexRange::new(0, 4).unwrap()]);
    }

    #[test]
    fn range_map_remaps_sorts_and_merges_source_spans() {
        let map = IlIndexRangeMap::new(vec![
            IlIndexRange::new(4, 5).unwrap(),
            IlIndexRange::EMPTY,
            IlIndexRange::new(0, 2).unwrap(),
            IlIndexRange::new(2, 4).unwrap(),
        ]);
        let address = Address::from(0x1000u64);
        let source_spans = [
            IlSourceSpan::try_new(IlIndexRange::new(0, 3).unwrap(), address, 0, 3).unwrap(),
            IlSourceSpan::try_new(IlIndexRange::new(3, 4).unwrap(), address, 3, 1).unwrap(),
        ];

        let spans = map.remap_source_spans(&source_spans).unwrap();

        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].destination(), IlIndexRange::new(0, 4).unwrap());
        assert_eq!(spans[0].first_source_index(), 0);
        assert_eq!(spans[0].source_count(), 4);
        assert_eq!(spans[1].destination(), IlIndexRange::new(4, 5).unwrap());
        assert_eq!(spans[1].first_source_index(), 0);
        assert_eq!(spans[1].source_count(), 3);
    }
}
