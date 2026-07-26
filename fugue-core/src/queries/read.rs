use std::ops::Bound;
use std::sync::Arc;

use super::{CallEdge, MappingRow, QueryPage, SwitchRow, SymbolRow};
use crate::ir::cfg::FlowTargets;
use crate::ir::{Address, CallGraphEdgeKey, FunctionRef, RawAddress, Reference, ReferenceTarget};
use crate::project::Project;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct ProjectRead<'p> {
    project: &'p Project,
}

impl<'p> ProjectRead<'p> {
    pub(crate) fn new(project: &'p Project) -> Self {
        Self { project }
    }

    pub(crate) fn project(&self) -> &Project {
        self.project
    }

    pub(crate) fn call_edge_page(
        &self,
        after: Option<CallEdge>,
        limit: usize,
    ) -> QueryPage<CallEdge> {
        let after = after.map(|edge| CallGraphEdgeKey::new(edge.source(), edge.target()));
        let edges = self
            .project
            .call_graph()
            .edges(after)
            .unwrap_or_else(|err| err.into_fatal())
            .map(|result| {
                result
                    .map(|edge| CallEdge::new(edge.source(), edge.target()))
                    .unwrap_or_else(|err| err.into_fatal())
            });

        Self::page(edges, limit)
    }

    pub(crate) fn function(&self, entry: Address) -> Option<FunctionRef<'_>> {
        self.project.functions().get_by_address(entry)
    }

    pub(crate) fn caller_page(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        let callers = self
            .project
            .call_graph()
            .callers(entry, after)
            .unwrap_or_else(|err| err.into_fatal())
            .map(|result| result.unwrap_or_else(|err| err.into_fatal()));

        Self::page(callers, limit)
    }

    pub(crate) fn callee_page(
        &self,
        entry: Address,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        self.function(entry)
            .map(|function| self.function_callee_page(function, after, limit))
            .unwrap_or_else(|| QueryPage::new(Vec::new(), None))
    }

    pub(crate) fn flow_targets(&self, function: FunctionRef<'_>) -> Arc<FlowTargets> {
        let targets = function
            .flow_targets(self.project.blocks())
            .collect::<Vec<_>>();

        Arc::new(FlowTargets::new(targets))
    }

    pub(crate) fn function_page(
        &self,
        space: AddressSpaceId,
        after: Option<RawAddress>,
        limit: usize,
    ) -> QueryPage<Address> {
        Self::page(
            self.project
                .functions()
                .addresses_in_space_after(space, after),
            limit,
        )
    }

    pub(crate) fn mapping_page(
        &self,
        space: AddressSpaceId,
        after: Option<MappingRow>,
        limit: usize,
    ) -> QueryPage<MappingRow> {
        let limit = Self::limit(limit);
        let Ok(views) = self
            .project
            .segments()
            .iter_views_from(space, after.map(|row| row.start()))
        else {
            return QueryPage::new(Vec::new(), None);
        };

        let mut rows = Vec::with_capacity(limit + 1);
        let mut group = Vec::new();
        let mut current_start = None;

        for row in views.map(|view| MappingRow::from_view(&view)) {
            if current_start.is_some_and(|start| start != row.start()) {
                Self::push_ordered_group(&mut rows, &mut group, after, limit);
                if rows.len() > limit {
                    break;
                }
            }

            current_start = Some(row.start());
            group.push(row);
        }

        if rows.len() <= limit {
            Self::push_ordered_group(&mut rows, &mut group, after, limit);
        }

        Self::page(rows, limit)
    }

    pub(crate) fn symbol_page(
        &self,
        after: Option<SymbolRow>,
        limit: usize,
    ) -> QueryPage<SymbolRow> {
        let limit = Self::limit(limit);
        let start = after.map_or(Bound::Unbounded, |after| Bound::Included(after.address()));
        let symbols = self
            .project
            .symbols()
            .range_by_address((start, Bound::Unbounded))
            .map(|(_, entry)| SymbolRow::from_entry(&entry));

        let mut rows = Vec::with_capacity(limit + 1);
        let mut group = Vec::new();
        let mut current_address = None;

        for row in symbols {
            if current_address.is_some_and(|address| address != row.address()) {
                Self::push_ordered_group(&mut rows, &mut group, after, limit);
                if rows.len() > limit {
                    break;
                }
            }

            current_address = Some(row.address());
            group.push(row);
        }

        if rows.len() <= limit {
            Self::push_ordered_group(&mut rows, &mut group, after, limit);
        }

        Self::page(rows, limit)
    }

    pub(crate) fn switch_at(&self, branch: Address) -> Option<SwitchRow> {
        self.project
            .switches()
            .get_by_branch(branch)
            .map(|switch| SwitchRow::from(&*switch))
    }

    pub(crate) fn switch_page(
        &self,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<SwitchRow, Address> {
        let rows = self
            .project
            .switches()
            .entries_after(after)
            .map(|switch| SwitchRow::from(&*switch));

        Self::page_by(rows, limit, SwitchRow::branch)
    }

    pub(crate) fn symbol_page_at(
        &self,
        address: Address,
        after: Option<SymbolRow>,
        limit: usize,
    ) -> QueryPage<SymbolRow> {
        let mut rows = self
            .project
            .symbols()
            .get_by_address(address)
            .map(|(_, entry)| SymbolRow::from_entry(&entry))
            .filter(|row| after.is_none_or(|after| *row > after))
            .collect::<Vec<_>>();
        rows.sort();

        Self::page(rows, limit)
    }

    pub(crate) fn outgoing_reference_page(
        &self,
        from: Address,
        after: Option<Reference>,
        limit: usize,
    ) -> QueryPage<Reference> {
        let references = self
            .project
            .references()
            .references_from(from, after.as_ref())
            .unwrap_or_else(|err| err.into_fatal())
            .map(|result| result.unwrap_or_else(|err| err.into_fatal()));

        Self::page(references, limit)
    }

    pub(crate) fn incoming_reference_page(
        &self,
        target: ReferenceTarget,
        after: Option<Reference>,
        limit: usize,
    ) -> QueryPage<Reference> {
        let references = self
            .project
            .references()
            .references_to(target, after.as_ref())
            .unwrap_or_else(|err| err.into_fatal())
            .map(|result| result.unwrap_or_else(|err| err.into_fatal()));

        Self::page(references, limit)
    }

    pub(crate) fn function_callee_page(
        &self,
        function: FunctionRef<'_>,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        let callees = self
            .project
            .call_graph()
            .callees(function.entry(), after)
            .unwrap_or_else(|err| err.into_fatal())
            .map(|result| result.unwrap_or_else(|err| err.into_fatal()));

        Self::page(callees, limit)
    }

    fn limit(limit: usize) -> usize {
        limit.clamp(1, super::MAX_QUERY_PAGE_COUNT)
    }

    fn push_ordered_group<T>(
        rows: &mut Vec<T>,
        group: &mut Vec<T>,
        after: Option<T>,
        limit: usize,
    ) where
        T: Copy + Ord,
    {
        group.sort();
        rows.extend(
            group
                .drain(..)
                .filter(|row| after.is_none_or(|after| *row > after))
                .take(limit + 1 - rows.len()),
        );
    }

    fn page<T>(source: impl IntoIterator<Item = T>, limit: usize) -> QueryPage<T>
    where
        T: Clone,
    {
        Self::page_by(source, limit, Clone::clone)
    }

    fn page_by<T, C>(
        source: impl IntoIterator<Item = T>,
        limit: usize,
        cursor: impl FnOnce(&T) -> C,
    ) -> QueryPage<T, C> {
        let limit = Self::limit(limit);
        let mut entries = Vec::with_capacity(limit + 1);
        for entry in source.into_iter().take(limit + 1) {
            entries.push(entry);
        }
        let next_cursor = (entries.len() > limit).then(|| cursor(&entries[limit - 1]));
        entries.truncate(limit);

        QueryPage::new(entries, next_cursor)
    }
}
