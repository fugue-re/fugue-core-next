use super::MCodeSsaConstruction;
use crate::il::common::{IlError, IlIndexRange, IlParentSpan, IlSourceSpan};

impl MCodeSsaConstruction<'_, '_> {
    pub(super) fn remap_source_spans(&self) -> Result<Vec<IlSourceSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut spans = Vec::new();
        for span in self.source.source_spans() {
            self.remap_destination_spans(span.destination(), &mut destinations)?;
            for &destination in &destinations {
                spans.push(IlSourceSpan::new(
                    destination,
                    span.address(),
                    span.first_pcode_index(),
                    span.pcode_count(),
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

    pub(super) fn remap_parent_spans(&self) -> Result<Vec<IlParentSpan>, IlError> {
        let mut remapped = Vec::new();
        for (index, &destination) in self.operation_ranges.iter().enumerate() {
            if destination.is_empty() {
                continue;
            }
            let source = IlIndexRange::new(index, index + 1)?;
            remapped.push(IlParentSpan::new(destination, source));
        }
        remapped.sort_unstable_by_key(|span| span.destination().start());

        let mut spans = Vec::<IlParentSpan>::with_capacity(remapped.len());
        for span in remapped {
            if let Some(previous) = spans.last_mut()
                && previous.try_merge(span)?
            {
                continue;
            }
            spans.push(span);
        }

        Ok(spans)
    }

    fn remap_destination_spans(
        &self,
        source: IlIndexRange,
        destinations: &mut Vec<IlIndexRange>,
    ) -> Result<(), IlError> {
        destinations.clear();
        for index in source.start()..source.end() {
            let range = self.operation_ranges[index];
            if range.is_empty() {
                continue;
            }
            if let Some(previous) = destinations.last_mut()
                && previous.end() == range.start()
            {
                *previous = IlIndexRange::new(previous.start(), range.end())?;
            } else {
                destinations.push(range);
            }
        }

        Ok(())
    }
}
