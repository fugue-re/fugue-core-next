use crate::analysis::AnalysisError;
use crate::engine::ProjectView;
use crate::ir::SymbolProperties;
use crate::ir::symbol::existing_symbol;
use crate::platform::OperatingSystem;
use crate::platform::non_returning::is_non_returning_extern;
use crate::project::Project;

const NON_RETURNING_EXTERNS_ANALYSER: &str = "non-returning-externs";

#[derive(Debug, Clone, Copy)]
pub struct NonReturningExterns {
    operating_system: OperatingSystem,
}

impl NonReturningExterns {
    pub fn new(operating_system: OperatingSystem) -> Self {
        Self { operating_system }
    }

    pub fn operating_system(&self) -> OperatingSystem {
        self.operating_system
    }
}

impl NonReturningExterns {
    pub fn analyse(&self, project: &mut Project) -> Result<(), AnalysisError> {
        let view = ProjectView::new(project);
        let marked = view
            .symbols()
            .iter()
            .filter(|(_, entry)| entry.is_function() && !entry.is_non_returning())
            .filter(|(_, entry)| {
                let name = entry.symbol();
                let base = name
                    .rsplit_once('!')
                    .map_or(name.as_str(), |(_, base)| base);
                existing_symbol(base)
                    .is_some_and(|base| is_non_returning_extern(self.operating_system, base))
            })
            .map(|(id, entry)| (id, entry.properties() | SymbolProperties::NON_RETURNING))
            .collect::<Vec<_>>();
        let reads = view.into_reads();
        let mut transaction = project.transaction(NON_RETURNING_EXTERNS_ANALYSER);
        transaction.absorb_reads(&reads);

        marked.into_iter().try_for_each(|(id, properties)| {
            transaction
                .update_symbol_properties(id, properties)
                .map(|_| ())
                .map_err(|error| AnalysisError::pass_failed(NON_RETURNING_EXTERNS_ANALYSER, error))
        })?;
        transaction
            .commit()
            .map(|_| ())
            .map_err(|error| AnalysisError::pass_failed(NON_RETURNING_EXTERNS_ANALYSER, error))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::loader::{Loadable, Loader};

    #[test]
    #[ignore = "requires binary test fixtures"]
    fn test_non_returning_externs_are_marked() -> Result<(), Box<dyn std::error::Error>> {
        for (path, expected) in [
            ("tests/ls.elf", ["abort", "__stack_chk_fail"].as_slice()),
            ("tests/hello-pe.exe", ["ExitProcess"].as_slice()),
        ] {
            let loader = Loader::from_file(path)?;
            let mut project = Project::new_transient(&loader)?;

            assert!(
                project
                    .symbols()
                    .iter()
                    .all(|(_, entry)| !entry.is_non_returning()),
                "{path} has marked symbols before the analysis runs"
            );

            let os = loader.platform().os();
            NonReturningExterns::new(os).analyse(&mut project)?;

            for name in expected {
                let marked = project
                    .symbols()
                    .iter()
                    .filter(|(_, entry)| {
                        let symbol = entry.symbol();
                        symbol.rsplit_once('!').map_or(symbol.as_str(), |(_, n)| n) == *name
                    })
                    .collect::<Vec<_>>();

                assert!(!marked.is_empty(), "no {name} symbol in {path}");
                assert!(
                    marked.iter().any(|(_, entry)| entry.is_non_returning()),
                    "{name} is not marked non-returning in {path}"
                );
            }
        }

        Ok(())
    }
}
