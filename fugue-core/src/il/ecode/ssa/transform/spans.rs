use super::ECodeSsaConstruction;
use crate::il::common::{IlError, IlIndexRange, IlParentSpan, IlSourceSpan};

impl ECodeSsaConstruction<'_, '_> {
    pub(crate) fn remap_source_spans(&self) -> Result<Vec<IlSourceSpan>, IlError> {
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

    pub(crate) fn remap_parent_spans(&self) -> Result<Vec<IlParentSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut spans = Vec::new();

        for span in self.source.parent_spans() {
            self.remap_destination_spans(span.destination(), &mut destinations)?;
            for &destination in &destinations {
                spans.push(IlParentSpan::new(destination, span.source()));
            }
        }

        spans.sort_unstable_by_key(|span| span.destination().start());
        Ok(spans)
    }

    fn remap_destination_spans(
        &self,
        destination: IlIndexRange,
        spans: &mut Vec<IlIndexRange>,
    ) -> Result<(), IlError> {
        spans.clear();

        for statement_index in destination.start()..destination.end() {
            let range = self.statement_ranges[statement_index];

            if range.is_empty() {
                continue;
            }

            if let Some(previous) = spans.last_mut()
                && previous.end() == range.start()
            {
                *previous = IlIndexRange::new(previous.start(), range.end())?;
            } else {
                spans.push(range);
            }
        }

        Ok(())
    }
}
