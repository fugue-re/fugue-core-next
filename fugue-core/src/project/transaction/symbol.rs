use std::collections::BTreeSet;

use super::ProjectTransaction;
use crate::ir::{Address, Symbol, SymbolEntry, SymbolId, SymbolIndex, SymbolProperties};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub fn add_symbol(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, ProjectError> {
        let entry = entry.with_index(index);
        if let Some(existing_id) = self.staged_symbol_id_by_index(index) {
            let Some(mut existing) = self.staged_symbol(existing_id)? else {
                unreachable!("staged symbol index refers to an existing entry");
            };
            if existing == entry {
                return Ok(existing_id);
            }

            if existing.indices().len() > 1 {
                existing.remove_index(index);
                self.stage_symbol(existing_id, Some(existing))?;
            } else {
                self.remove_staged_symbol(existing_id)?;
            }
        }

        self.insert_or_update_symbol(index, entry)
    }

    pub fn set_symbol_properties(
        &mut self,
        id: SymbolId,
        properties: SymbolProperties,
    ) -> Result<bool, ProjectError> {
        let Some(mut entry) = self.staged_symbol(id)? else {
            return Ok(false);
        };

        if entry.properties() == properties {
            return Ok(false);
        }

        entry.set_properties(properties);
        self.stage_symbol(id, Some(entry))?;

        Ok(true)
    }

    pub fn remove_symbols_by_name(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Result<usize, ProjectError> {
        let symbol = Symbol::from_existing(symbol.as_ref());
        let Some(symbol) = symbol else {
            return Ok(0);
        };
        let ids = self.symbol_ids_matching(|entry| entry.symbol() == symbol)?;
        let count = ids.len();
        for id in ids {
            self.remove_staged_symbol(id)?;
        }
        Ok(count)
    }

    pub fn remove_symbols_by_address(&mut self, address: Address) -> Result<usize, ProjectError> {
        let ids = self.symbol_ids_matching(|entry| entry.address() == address)?;
        let count = ids.len();
        for id in ids {
            self.remove_staged_symbol(id)?;
        }
        Ok(count)
    }

    pub fn remove_symbol_by_id(&mut self, id: SymbolId) -> Result<bool, ProjectError> {
        if self.staged_symbol(id)?.is_none() {
            return Ok(false);
        }
        self.remove_staged_symbol(id)?;

        Ok(true)
    }

    pub fn remove_symbol_by_index(&mut self, index: SymbolIndex) -> Result<bool, ProjectError> {
        let Some(id) = self.staged_symbol_id_by_index(index) else {
            return Ok(false);
        };
        self.remove_staged_symbol(id)?;

        Ok(true)
    }

    fn insert_or_update_symbol(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, ProjectError> {
        if let Some(id) = self.find_symbol_referent(&entry)? {
            let mut existing = self
                .staged_symbol(id)?
                .expect("symbol referent was resolved from an existing entry");
            existing.add_index(index);
            existing.update_visibility(entry.properties());
            self.stage_symbol(id, Some(existing))?;
            return Ok(id);
        }

        let id = self
            .project
            .symbols
            .pending_id(self.symbol_reservations.len());
        self.symbol_reservations.push(id);
        self.stage_symbol(id, Some(entry))?;
        Ok(id)
    }

    fn find_symbol_referent(&self, entry: &SymbolEntry) -> Result<Option<SymbolId>, ProjectError> {
        for (id, _) in self.project.symbols.get_by_address(entry.address()) {
            if let Some(candidate) = self.staged_symbol(id)?
                && candidate.has_same_referent(entry)
            {
                return Ok(Some(id));
            }
        }

        Ok(self.staged_symbols.iter().find_map(|(&id, candidate)| {
            candidate
                .as_ref()
                .is_some_and(|candidate| candidate.has_same_referent(entry))
                .then_some(id)
        }))
    }

    fn staged_symbol(&self, id: SymbolId) -> Result<Option<SymbolEntry>, ProjectError> {
        match self.staged_symbols.get(&id) {
            Some(entry) => Ok(entry.clone()),
            None => Ok(self
                .project
                .symbols
                .try_get_by_id(id)?
                .map(|entry| entry.as_ref().clone())),
        }
    }

    fn staged_symbol_id_by_index(&self, index: SymbolIndex) -> Option<SymbolId> {
        match self.symbol_indices.get(&index) {
            Some(id) => *id,
            None => self.project.symbols.get_id_by_index(index).and_then(|id| {
                self.staged_symbols.get(&id).map_or(Some(id), |entry| {
                    entry
                        .as_ref()
                        .filter(|entry| entry.indices().contains(&index))
                        .map(|_| id)
                })
            }),
        }
    }

    fn stage_symbol(
        &mut self,
        id: SymbolId,
        entry: Option<SymbolEntry>,
    ) -> Result<(), ProjectError> {
        if let Some(previous) = self.staged_symbol(id)? {
            for &index in previous.indices() {
                if self.staged_symbol_id_by_index(index) == Some(id) {
                    self.symbol_indices.insert(index, None);
                }
            }
        }
        if let Some(entry) = &entry {
            for &index in entry.indices() {
                self.symbol_indices.insert(index, Some(id));
            }
        }
        self.staged_symbols.insert(id, entry);
        Ok(())
    }

    fn remove_staged_symbol(&mut self, id: SymbolId) -> Result<(), ProjectError> {
        self.stage_symbol(id, None)?;
        if self.project.symbols.try_get_by_id(id)?.is_none() {
            self.staged_symbols.remove(&id);
            self.cancelled_symbols.push(id);
        }
        Ok(())
    }

    fn symbol_ids_matching(
        &self,
        mut predicate: impl FnMut(&SymbolEntry) -> bool,
    ) -> Result<BTreeSet<SymbolId>, ProjectError> {
        let mut ids = BTreeSet::new();
        for (id, _) in self.project.symbols.iter() {
            if let Some(entry) = self.staged_symbol(id)?
                && predicate(&entry)
            {
                ids.insert(id);
            }
        }
        for (&id, entry) in &self.staged_symbols {
            if entry.as_ref().is_some_and(&mut predicate) {
                ids.insert(id);
            } else {
                ids.remove(&id);
            }
        }
        Ok(ids)
    }
}
