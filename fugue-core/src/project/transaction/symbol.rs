use super::ProjectTransaction;
use crate::ir::{Address, SymbolEntry, SymbolId, SymbolIndex, SymbolProperties};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub fn add_symbol(
        &mut self,
        index: SymbolIndex,
        entry: SymbolEntry,
    ) -> Result<SymbolId, ProjectError> {
        self.symbol_staging
            .add(&self.project.symbols, index, entry)
            .map_err(ProjectError::from)
    }

    pub fn update_symbol_properties(
        &mut self,
        id: SymbolId,
        properties: SymbolProperties,
    ) -> Result<bool, ProjectError> {
        self.symbol_staging
            .set_properties(&self.project.symbols, id, properties)
            .map_err(ProjectError::from)
    }

    pub fn remove_symbols_by_name(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> Result<usize, ProjectError> {
        self.symbol_staging
            .remove_by_name(&self.project.symbols, symbol)
            .map_err(ProjectError::from)
    }

    pub fn remove_symbols_by_address(&mut self, address: Address) -> Result<usize, ProjectError> {
        self.symbol_staging
            .remove_by_address(&self.project.symbols, address)
            .map_err(ProjectError::from)
    }

    pub fn remove_symbol_by_id(&mut self, id: SymbolId) -> Result<bool, ProjectError> {
        self.symbol_staging
            .remove_by_id(&self.project.symbols, id)
            .map_err(ProjectError::from)
    }

    pub fn remove_symbol_by_index(&mut self, index: SymbolIndex) -> Result<bool, ProjectError> {
        self.symbol_staging
            .remove_by_index(&self.project.symbols, index)
            .map_err(ProjectError::from)
    }
}
