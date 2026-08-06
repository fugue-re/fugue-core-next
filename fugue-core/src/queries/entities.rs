use std::cmp::Ordering as CmpOrdering;
use std::sync::Arc;

use crate::ir::{
    Address, Problem, ProblemKey, ProblemKind, ProblemScope, SegmentProperties, Switch, Symbol,
    SymbolEntry, SymbolProperties,
};
use crate::storage::segments::mapping::SegmentMappingId;
use crate::storage::segments::view::SegmentMappingView;
use crate::types::Confidence;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryPage<T, C = T> {
    entries: Arc<[T]>,
    next_cursor: Option<C>,
}

impl<T, C> QueryPage<T, C> {
    pub fn new(entries: impl Into<Arc<[T]>>, next_cursor: Option<C>) -> Self {
        Self {
            entries: entries.into(),
            next_cursor,
        }
    }

    pub fn entries(&self) -> &[T] {
        &self.entries
    }

    pub fn next_cursor(&self) -> Option<&C> {
        self.next_cursor.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallEdge {
    source: Address,
    target: Address,
}

impl CallEdge {
    pub fn new(source: impl Into<Address>, target: impl Into<Address>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }

    pub fn source(&self) -> Address {
        self.source
    }

    pub fn target(&self) -> Address {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolEntity {
    address: Address,
    properties: SymbolProperties,
    symbol: Symbol,
}

impl SymbolEntity {
    pub fn new(
        address: impl Into<Address>,
        symbol: impl Into<Symbol>,
        properties: SymbolProperties,
    ) -> Self {
        Self {
            address: address.into(),
            properties,
            symbol: symbol.into(),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn properties(&self) -> SymbolProperties {
        self.properties
    }

    pub fn symbol(&self) -> Symbol {
        self.symbol
    }
}

impl From<&SymbolEntry> for SymbolEntity {
    fn from(entry: &SymbolEntry) -> Self {
        Self::new(entry.address(), entry.symbol(), entry.properties())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchEntity {
    switch: Switch,
}

impl SwitchEntity {
    pub fn branch(&self) -> Address {
        self.switch.branch()
    }

    pub fn switch(&self) -> &Switch {
        &self.switch
    }

    pub fn case_count(&self) -> usize {
        self.switch.case_count()
    }

    pub fn has_default(&self) -> bool {
        self.switch.has_default()
    }

    pub fn confidence(&self) -> Confidence {
        self.switch.confidence()
    }
}

impl From<&Switch> for SwitchEntity {
    fn from(switch: &Switch) -> Self {
        Self {
            switch: switch.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemEntity {
    problem: Problem,
}

impl ProblemEntity {
    pub fn address(&self) -> Option<Address> {
        self.problem.address()
    }

    pub fn scope(&self) -> ProblemScope {
        self.problem.scope()
    }

    pub fn kind(&self) -> ProblemKind {
        self.problem.kind()
    }

    pub fn key(&self) -> ProblemKey {
        self.problem.key()
    }

    pub fn attempts(&self) -> u8 {
        self.problem.attempts()
    }

    pub fn problem(&self) -> &Problem {
        &self.problem
    }
}

impl From<&Problem> for ProblemEntity {
    fn from(problem: &Problem) -> Self {
        Self {
            problem: problem.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappingEntity {
    mapping: SegmentMappingId,
    start: Address,
    size: u64,
    properties: SegmentProperties,
}

impl MappingEntity {
    pub fn new(
        mapping: SegmentMappingId,
        start: impl Into<Address>,
        size: u64,
        properties: SegmentProperties,
    ) -> Self {
        Self {
            mapping,
            start: start.into(),
            size,
            properties,
        }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn start(&self) -> Address {
        self.start
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn properties(&self) -> SegmentProperties {
        self.properties
    }
}

impl From<&SegmentMappingView<'_>> for MappingEntity {
    fn from(view: &SegmentMappingView<'_>) -> Self {
        Self::new(
            view.mapping_ref().mapping_id(),
            view.start(),
            view.size(),
            view.properties(),
        )
    }
}

impl PartialOrd for MappingEntity {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for MappingEntity {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.start
            .cmp(&other.start)
            .then_with(|| self.mapping.cmp(&other.mapping))
            .then_with(|| self.size.cmp(&other.size))
            .then_with(|| self.properties.cmp(&other.properties))
    }
}

#[cfg(test)]
mod test {
    use super::QueryPage;

    #[test]
    fn query_page_exposes_entries_and_next_cursor() {
        let page = QueryPage::new([1, 2, 3], Some(3));

        assert_eq!(page.entries(), &[1, 2, 3]);
        assert_eq!(page.next_cursor(), Some(&3));
    }
}
