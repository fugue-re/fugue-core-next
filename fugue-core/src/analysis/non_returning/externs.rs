use crate::analysis::AnalysisError;
use crate::engine::{Analyser, AnalyserProvider, AnalysisContext};
use crate::extension;
use crate::ir::SymbolProperties;
use crate::ir::symbol::existing_symbol;
use crate::platform::non_returning::is_non_returning_extern;
use crate::project::{AnalysisPhase, ChangeKinds, Project};

const NON_RETURNING_EXTERNS_ANALYSER: &str = "non-returning-externs";

#[derive(Debug, Clone, Copy, Default)]
pub struct NonReturningExterns;

impl Analyser for NonReturningExterns {
    fn name(&self) -> &'static str {
        NON_RETURNING_EXTERNS_ANALYSER
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::SEGMENT_MAPPED | ChangeKinds::SYMBOLS
    }

    fn phase(&self) -> AnalysisPhase {
        AnalysisPhase::Decode
    }

    fn can_analyse(&self, project: &Project) -> bool {
        let _ = project;
        true
    }

    fn analyse(&mut self, context: &mut AnalysisContext<'_, '_>) -> Result<(), AnalysisError> {
        let project = &context.project;
        let operating_system = project.platform().os();
        for (id, entry) in project
            .symbols()
            .iter()
            .filter(|(_, entry)| {
                entry.is_extern() && entry.is_function() && !entry.is_non_returning()
            })
            .filter(|(_, entry)| {
                let name = entry.symbol();
                let base = name
                    .rsplit_once('!')
                    .map_or(name.as_str(), |(_, base)| base);
                existing_symbol(base)
                    .is_some_and(|base| is_non_returning_extern(operating_system, base))
            })
        {
            context
                .updates
                .update_symbol_properties(id, entry.properties() | SymbolProperties::NON_RETURNING);
        }
        Ok(())
    }

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::SYMBOL_CHANGED
    }
}

extension::submit! {
    AnalyserProvider::new::<NonReturningExterns>(NON_RETURNING_EXTERNS_ANALYSER, |_project| {
        Ok(Box::new(NonReturningExterns))
    })
}
