use std::collections::BTreeSet;
use std::sync::Arc;

use super::{CallEdge, MappingRecord, QueryPage, SymbolRecord};
use crate::ir::block::table::CodeBlockRef;
use crate::ir::cfg::{FlowGraph, FlowTarget};
use crate::ir::function::table::FunctionRef;
use crate::ir::{Address, InsnTargetKind};
use crate::project::Project;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct ProjectRead<'p> {
    project: &'p Project,
}

impl<'p> ProjectRead<'p> {
    pub(crate) fn new(project: &'p Project) -> Self {
        Self { project }
    }

    pub(crate) fn call_edges(&self, after: Option<CallEdge>, limit: usize) -> QueryPage<CallEdge> {
        let limit = Self::limit(limit);
        let mut edges = BTreeSet::new();

        for function in self.project.functions().iter() {
            let caller = function.entry();
            self.visit_function_call_targets(function, |callee| {
                let edge = CallEdge::new(caller, callee);
                if after.is_none_or(|after| edge > after) {
                    edges.insert(edge);
                    if edges.len() > limit + 1 {
                        edges.pop_last();
                    }
                }

                true
            });
        }

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
        let limit = Self::limit(limit);
        let mut callers = BTreeSet::new();

        for function in self.project.functions().iter() {
            let source = function.entry();
            if after.is_none_or(|after| source > after) && self.function_calls(function, entry) {
                callers.insert(source);
                if callers.len() > limit + 1 {
                    callers.pop_last();
                }
            }
        }

        Self::page(callers, limit)
    }

    pub(crate) fn flow_graph(&self, function: FunctionRef<'_>) -> Arc<FlowGraph> {
        let blocks = function
            .blocks()
            .filter_map(|(_, id)| self.project.blocks().get_by_id(id));

        Arc::new(FlowGraph::new(Self::flow_targets(blocks)))
    }

    pub(crate) fn function_page(&self, after: Option<Address>, limit: usize) -> QueryPage<Address> {
        Self::page(
            self.project
                .functions()
                .addresses()
                .filter(|entry| after.is_none_or(|after| *entry > after)),
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
        let mut mappings = BTreeSet::new();
        let Ok(views) = self.project.segments().iter_views(space) else {
            return QueryPage::new(Vec::new(), None);
        };

        for view in views {
            Self::insert_mapping_record(
                &mut mappings,
                MappingRecord::from_view(&view),
                after,
                limit,
            );
        }

        Self::page(mappings, limit)
    }

    pub(crate) fn symbol_page(
        &self,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> QueryPage<SymbolRecord> {
        let limit = Self::limit(limit);
        let mut symbols = BTreeSet::new();

        for (_, entry) in self.project.symbols().iter_by_address() {
            Self::insert_symbol_record(&mut symbols, SymbolRecord::from_entry(entry), after, limit);
        }

        Self::page(symbols, limit)
    }

    pub(crate) fn symbols_at(
        &self,
        address: Address,
        after: Option<SymbolRecord>,
        limit: usize,
    ) -> QueryPage<SymbolRecord> {
        let limit = Self::limit(limit);
        let mut symbols = BTreeSet::new();

        for (_, entry) in self.project.symbols().get_by_address(address) {
            Self::insert_symbol_record(&mut symbols, SymbolRecord::from_entry(entry), after, limit);
        }

        Self::page(symbols, limit)
    }

    fn flow_targets<'a>(blocks: impl IntoIterator<Item = CodeBlockRef<'a>>) -> Vec<FlowTarget> {
        let mut flow_targets = Vec::new();

        for block in blocks {
            for insn in block.instructions().iter() {
                for (target, _, to) in insn.iter_targets() {
                    if let Some(flow_target) = FlowTarget::from_insn_target(insn, target, to) {
                        flow_targets.push(flow_target);
                    }
                }
            }
        }

        flow_targets
    }

    pub(crate) fn function_callee_page(
        &self,
        function: FunctionRef<'_>,
        after: Option<Address>,
        limit: usize,
    ) -> QueryPage<Address> {
        let limit = Self::limit(limit);
        let mut callees = BTreeSet::new();

        self.visit_function_call_targets(function, |callee| {
            if after.is_none_or(|after| callee > after) {
                callees.insert(callee);
                if callees.len() > limit + 1 {
                    callees.pop_last();
                }
            }

            true
        });

        Self::page(callees, limit)
    }

    fn function_calls(&self, function: FunctionRef<'_>, target: Address) -> bool {
        let mut found = false;

        self.visit_function_call_targets(function, |callee| {
            found = callee == target;
            !found
        });

        found
    }

    fn insert_mapping_record(
        mappings: &mut BTreeSet<MappingRecord>,
        record: MappingRecord,
        after: Option<MappingRecord>,
        limit: usize,
    ) {
        if after.is_none_or(|after| record > after) {
            mappings.insert(record);
            if mappings.len() > limit + 1 {
                mappings.pop_last();
            }
        }
    }

    fn insert_symbol_record(
        symbols: &mut BTreeSet<SymbolRecord>,
        record: SymbolRecord,
        after: Option<SymbolRecord>,
        limit: usize,
    ) {
        if after.is_none_or(|after| record > after) {
            symbols.insert(record);
            if symbols.len() > limit + 1 {
                symbols.pop_last();
            }
        }
    }

    fn limit(limit: usize) -> usize {
        limit.clamp(1, super::MAX_QUERY_PAGE_LEN)
    }

    fn page<T>(source: impl IntoIterator<Item = T>, limit: usize) -> QueryPage<T>
    where
        T: Clone,
    {
        let limit = Self::limit(limit);
        let mut entries = Vec::with_capacity(limit + 1);
        for entry in source.into_iter().take(limit + 1) {
            entries.push(entry);
        }
        let next_cursor = (entries.len() > limit).then(|| entries[limit - 1].clone());
        entries.truncate(limit);

        QueryPage::new(entries, next_cursor)
    }

    fn visit_function_call_targets(
        &self,
        function: FunctionRef<'_>,
        mut visit: impl FnMut(Address) -> bool,
    ) {
        let blocks = function
            .blocks()
            .filter_map(|(_, id)| self.project.blocks().get_by_id(id));

        for block in blocks {
            for insn in block.instructions().iter() {
                for (target, kind, to) in insn.iter_targets() {
                    let is_call = kind == InsnTargetKind::Global
                        && FlowTarget::from_insn_target(insn, target, to)
                            .is_some_and(|flow_target| flow_target.kind().is_call());
                    if is_call && !visit(to) {
                        return;
                    }
                }
            }
        }
    }
}
