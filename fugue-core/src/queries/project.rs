use std::ops::Bound;
use std::sync::Arc;

use super::{
    CallEdge, MAX_QUERY_PAGE_SIZE, MappingEntity, ProblemEntity, QueryPage, SwitchEntity,
    SymbolEntity,
};
use crate::ir::cfg::FlowTargets;
use crate::ir::{
    Address, CallGraphEdgeKey, FunctionId, FunctionRef, ProblemKey, ProblemKind, Reference,
    ReferenceTarget,
};
use crate::project::{Project, ProjectError};
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct ProjectQuery<'p> {
    project: &'p Project,
}

impl<'p> ProjectQuery<'p> {
    pub(crate) fn new(project: &'p Project) -> Self {
        Self { project }
    }

    pub(crate) fn project(&self) -> &Project {
        self.project
    }

    pub(crate) fn function_at(&self, entry: Address) -> Option<FunctionId> {
        self.project
            .functions()
            .get_by_address(entry)
            .map(|function| function.id())
    }

    pub(crate) fn function_page(
        &self,
        space: AddressSpaceId,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        Self::page(
            self.project
                .functions()
                .addresses_in_space_after(space, after.map(|address| address.raw_address())),
            limit,
        )
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
        self.project
            .functions()
            .get_by_address(entry)
            .map(|function| self.function_callee_page(function, after, limit))
            .unwrap_or_else(|| QueryPage::new(Vec::new(), None))
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

    pub(crate) fn mapping_page(
        &self,
        space: AddressSpaceId,
        after: Option<MappingEntity>,
        limit: usize,
    ) -> Result<QueryPage<MappingEntity>, ProjectError> {
        let views = self
            .project
            .segments()
            .iter_views_from(space, after.map(|row| row.start()))?;

        Ok(Self::page_grouped(
            views.map(|view| MappingEntity::from(&view)),
            after,
            limit,
            MappingEntity::start,
        ))
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

    pub(crate) fn problem_at(&self, address: Address, kind: ProblemKind) -> Option<ProblemEntity> {
        self.project
            .problems()
            .get(address, kind)
            .map(|problem| ProblemEntity::from(&*problem))
    }

    pub(crate) fn problem_page(
        &self,
        after: Option<ProblemKey>,
        limit: usize,
    ) -> QueryPage<ProblemEntity, ProblemKey> {
        let rows = self
            .project
            .problems()
            .entries_after(after)
            .map(|problem| ProblemEntity::from(&*problem));

        Self::page_by(rows, limit, ProblemEntity::key)
    }

    pub(crate) fn switch_at(&self, branch: Address) -> Option<SwitchEntity> {
        self.project
            .switches()
            .get_by_branch(branch)
            .map(|switch| SwitchEntity::from(&*switch))
    }

    pub(crate) fn switch_page(
        &self,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<SwitchEntity, Address> {
        let rows = self
            .project
            .switches()
            .entries_after(after)
            .map(|switch| SwitchEntity::from(&*switch));

        Self::page_by(rows, limit, SwitchEntity::branch)
    }

    pub(crate) fn symbol_page(
        &self,
        after: Option<SymbolEntity>,
        limit: usize,
    ) -> QueryPage<SymbolEntity> {
        let start = after.map_or(Bound::Unbounded, |after| Bound::Included(after.address()));
        let symbols = self
            .project
            .symbols()
            .range_by_address((start, Bound::Unbounded))
            .map(|(_, entry)| SymbolEntity::from(&*entry));

        Self::page_grouped(symbols, after, limit, SymbolEntity::address)
    }

    pub(crate) fn symbol_page_at(
        &self,
        address: Address,
        after: Option<SymbolEntity>,
        limit: usize,
    ) -> QueryPage<SymbolEntity> {
        let mut rows = self
            .project
            .symbols()
            .get_by_address(address)
            .map(|(_, entry)| SymbolEntity::from(&*entry))
            .filter(|row| after.is_none_or(|after| *row > after))
            .collect::<Vec<_>>();
        rows.sort();

        Self::page(rows, limit)
    }

    pub(crate) fn flow_targets(&self, function: FunctionRef<'_>) -> Arc<FlowTargets> {
        let targets = function
            .flow_targets(self.project.blocks())
            .collect::<Vec<_>>();

        Arc::new(FlowTargets::new(targets))
    }

    fn push_ordered_group<T>(rows: &mut Vec<T>, group: &mut Vec<T>, after: Option<T>, limit: usize)
    where
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

    fn page_grouped<T, K>(
        source: impl IntoIterator<Item = T>,
        after: Option<T>,
        limit: usize,
        group_key: impl Fn(&T) -> K,
    ) -> QueryPage<T>
    where
        K: Copy + Eq,
        T: Clone + Copy + Ord,
    {
        let limit = limit.clamp(1, MAX_QUERY_PAGE_SIZE);
        let mut rows = Vec::with_capacity(limit + 1);
        let mut group = Vec::new();
        let mut current_key = None;

        for row in source {
            let key = group_key(&row);
            if current_key.is_some_and(|current| current != key) {
                Self::push_ordered_group(&mut rows, &mut group, after, limit);
                if rows.len() > limit {
                    break;
                }
            }

            current_key = Some(key);
            group.push(row);
        }

        if rows.len() <= limit {
            Self::push_ordered_group(&mut rows, &mut group, after, limit);
        }

        Self::page(rows, limit)
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
        let limit = limit.clamp(1, MAX_QUERY_PAGE_SIZE);
        let mut entries = Vec::with_capacity(limit + 1);
        for entry in source.into_iter().take(limit + 1) {
            entries.push(entry);
        }
        let next_cursor = (entries.len() > limit).then(|| cursor(&entries[limit - 1]));
        entries.truncate(limit);

        QueryPage::new(entries, next_cursor)
    }
}
