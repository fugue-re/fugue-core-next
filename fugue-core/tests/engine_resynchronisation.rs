use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::time::Duration;

use fugue_core::engine::change::{ChangeRecord, ChangeSet};
use fugue_core::engine::{AnalysisEngine, ProjectUpdate};
use fugue_core::ir::{
    Address, Symbol, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::project::Project;
use fugue_core::queries::{QueryError, QueryReader};
use fugue_core::storage::TransientStorageProvider;

#[derive(Debug, Default, PartialEq, Eq)]
struct SymbolAgent {
    symbols: BTreeSet<(Address, Symbol)>,
}

impl SymbolAgent {
    fn apply(&mut self, changes: &ChangeSet, project: &QueryReader) -> Result<(), QueryError> {
        if changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::Resynchronise { .. }))
        {
            return self.resynchronise(project);
        }

        for record in changes.records() {
            match record {
                ChangeRecord::SymbolAdded { address, symbol }
                | ChangeRecord::SymbolChanged { address, symbol } => {
                    self.symbols.insert((*address, *symbol));
                }
                ChangeRecord::SymbolRemoved { address, symbol } => {
                    self.symbols.remove(&(*address, *symbol));
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn resynchronise(&mut self, project: &QueryReader) -> Result<(), QueryError> {
        self.symbols.clear();
        for symbol in project.symbols() {
            let symbol = symbol?;
            self.symbols.insert((symbol.address(), symbol.symbol()));
        }
        Ok(())
    }
}

#[test]
fn incremental_and_resynchronised_agents_converge() -> Result<(), Box<dyn Error>> {
    let project = Project::from_file_with_provider::<TransientStorageProvider>("tests/ls.elf")?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;

    let reader = engine.query_reader()?;
    let incremental_changes = engine.subscribe().with_capacity(1024).build()?;
    let resynchronised_changes = engine.subscribe().with_capacity(1).build()?;

    let initial_incremental = incremental_changes.recv_timeout(Duration::from_secs(1))?;
    let mut incremental = SymbolAgent::default();
    incremental.apply(&initial_incremental, &reader)?;
    let initial_resynchronised = resynchronised_changes.recv_timeout(Duration::from_secs(1))?;
    let mut resynchronised = SymbolAgent::default();
    resynchronised.apply(&initial_resynchronised, &reader)?;

    let addresses = [entry, entry + 0x10u64, entry + 0x20u64];
    for (index, address) in addresses.into_iter().enumerate() {
        engine.apply_update(ProjectUpdate::add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(240), index),
            SymbolEntry::new(
                address,
                format!("resynchronisation_symbol_{index}"),
                SymbolProperties::LOCAL,
            ),
        ))?;
    }
    engine.remove_symbol(SymbolIndex::new(SymbolTableSelector::new(240), 1))?;
    engine.analyse()?;

    let incremental_batch = incremental_changes
        .drain()
        .ok_or_else(|| io::Error::other("incremental agent received no changes"))?;
    assert!(
        incremental_batch
            .records()
            .iter()
            .all(|record| !matches!(record, ChangeRecord::Resynchronise { .. })),
        "the incremental agent must receive detailed changes"
    );
    incremental.apply(&incremental_batch, &reader)?;

    let resynchronisation = resynchronised_changes.recv_batch()?;
    assert_eq!(
        resynchronisation.records(),
        [ChangeRecord::Resynchronise {
            to: reader.revision()?
        }]
    );
    resynchronised.apply(&resynchronisation, &reader)?;

    let mut current = SymbolAgent::default();
    current.resynchronise(&reader)?;
    assert_eq!(incremental, current);
    assert_eq!(resynchronised, current);

    Ok(())
}
