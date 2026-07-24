use std::ops::Bound;
use std::sync::Arc;

use super::{CallEdge, MappingRecord, QueryPage, SwitchRecord, SymbolRecord};
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

    pub(crate) fn callers_of(
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

    pub(crate) fn callees_of(
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
        after: Option<MappingRecord>,
        limit: usize,
    ) -> QueryPage<MappingRecord> {
        let limit = Self::limit(limit);
        let Ok(views) = self
            .project
            .segments()
            .iter_views_from(space, after.map(|record| record.start()))
        else {
            return QueryPage::new(Vec::new(), None);
        };

        let mut records = Vec::with_capacity(limit + 1);
        let mut group = Vec::new();
        let mut current_start = None;

        for record in views.map(|view| MappingRecord::from_view(&view)) {
            if current_start.is_some_and(|start| start != record.start()) {
                Self::push_ordered_group(&mut records, &mut group, after, limit);
                if records.len() > limit {
                    break;
                }
            }

            current_start = Some(record.start());
            group.push(record);
        }

        if records.len() <= limit {
            Self::push_ordered_group(&mut records, &mut group, after, limit);
        }

        Self::page(records, limit)
    }

    pub(crate) fn symbol_page(
        &self,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> QueryPage<SymbolRecord> {
        let limit = Self::limit(limit);
        let start = after.map_or(Bound::Unbounded, |after| Bound::Included(after.address()));
        let symbols = self
            .project
            .symbols()
            .range_by_address((start, Bound::Unbounded))
            .map(|(_, entry)| SymbolRecord::from_entry(&entry));

        let mut records = Vec::with_capacity(limit + 1);
        let mut group = Vec::new();
        let mut current_address = None;

        for record in symbols {
            if current_address.is_some_and(|address| address != record.address()) {
                Self::push_ordered_group(&mut records, &mut group, after, limit);
                if records.len() > limit {
                    break;
                }
            }

            current_address = Some(record.address());
            group.push(record);
        }

        if records.len() <= limit {
            Self::push_ordered_group(&mut records, &mut group, after, limit);
        }

        Self::page(records, limit)
    }

    pub(crate) fn switch_at(&self, branch: Address) -> Option<SwitchRecord> {
        self.project
            .switches()
            .get_by_branch(branch)
            .map(|switch| SwitchRecord::from(&*switch))
    }

    pub(crate) fn switch_page(
        &self,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<SwitchRecord, Address> {
        let records = self
            .project
            .switches()
            .entries_after(after)
            .map(|switch| SwitchRecord::from(&*switch));

        Self::page_by(records, limit, SwitchRecord::branch)
    }

    pub(crate) fn symbol_page_at(
        &self,
        address: Address,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> QueryPage<SymbolRecord> {
        let mut records = self
            .project
            .symbols()
            .get_by_address(address)
            .map(|(_, entry)| SymbolRecord::from_entry(&entry))
            .filter(|record| after.is_none_or(|after| *record > after))
            .collect::<Vec<_>>();
        records.sort();

        Self::page(records, limit)
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
        records: &mut Vec<T>,
        group: &mut Vec<T>,
        after: Option<T>,
        limit: usize,
    ) where
        T: Copy + Ord,
    {
        group.sort();
        records.extend(
            group
                .drain(..)
                .filter(|record| after.is_none_or(|after| *record > after))
                .take(limit + 1 - records.len()),
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
