use super::SsaConstruction;
use crate::il::common::{IlError, IlIndexRange, IlParentSpan, IlSourceSpan};

impl SsaConstruction<'_, '_> {
    pub(crate) fn remap_source_spans(&self) -> Result<Vec<IlSourceSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut runs = Vec::new();

        for run in self.source.source_spans() {
            self.remap_destination_runs(run.destination(), &mut destinations)?;
            for &destination in &destinations {
                runs.push(IlSourceSpan::new(
                    destination,
                    run.address(),
                    run.first_pcode_index(),
                    run.pcode_count(),
                ));
            }
        }

        runs.sort_unstable_by_key(|run| run.destination().start());
        let mut merged = Vec::<IlSourceSpan>::with_capacity(runs.len());
        for run in runs {
            if let Some(previous) = merged.last_mut()
                && previous.try_merge(run)?
            {
                continue;
            }
            merged.push(run);
        }
        Ok(merged)
    }

    pub(crate) fn remap_parent_spans(&self) -> Result<Vec<IlParentSpan>, IlError> {
        let mut destinations = Vec::new();
        let mut runs = Vec::new();

        for run in self.source.parent_spans() {
            self.remap_destination_runs(run.destination(), &mut destinations)?;
            for &destination in &destinations {
                runs.push(IlParentSpan::new(destination, run.source()));
            }
        }

        runs.sort_unstable_by_key(|run| run.destination().start());
        Ok(runs)
    }

    fn remap_destination_runs(
        &self,
        destination: IlIndexRange,
        runs: &mut Vec<IlIndexRange>,
    ) -> Result<(), IlError> {
        runs.clear();

        for statement_index in destination.start()..destination.end() {
            let range = self.statement_ranges[statement_index];

            if range.is_empty() {
                continue;
            }

            if let Some(previous) = runs.last_mut()
                && previous.end() == range.start()
            {
                *previous = IlIndexRange::new(previous.start(), range.end())?;
            } else {
                runs.push(range);
            }
        }

        Ok(())
    }
}
