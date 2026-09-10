use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flume::Sender;
use parking_lot::{ArcRwLockWriteGuard, RawRwLock, RwLock};

use crate::engine::Intake;
use crate::il::common::{IlError, IlFormId};
use crate::il::registry::IlRegistry;
use crate::ir::FunctionId;
use crate::project::{ChangeRecord, ChangeSet, Project, ProjectError};
use crate::queries::cache::{CacheLookup, QueryCache};
use crate::queries::index::ChangeIndex;
use crate::queries::reader::QueryReader;

pub(crate) type QueryPublicationGuard = ArcRwLockWriteGuard<RawRwLock, ()>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IlLookup {
    Current,
    Persisted,
}

pub(crate) struct QueryEngine {
    active: Arc<AtomicBool>,
    publication_lock: Arc<RwLock<()>>,
    project: Arc<RwLock<Project>>,
    cache: Arc<QueryCache>,
    changes: Arc<RwLock<ChangeIndex>>,
    registry: Arc<IlRegistry>,
}

impl QueryEngine {
    pub(crate) fn new(
        project: Arc<RwLock<Project>>,
        registry: Arc<IlRegistry>,
        lifted_cache_bytes: usize,
    ) -> Self {
        let revision = project.read().revision();
        Self {
            active: Arc::new(AtomicBool::new(true)),
            publication_lock: Arc::new(RwLock::new(())),
            project,
            cache: Arc::new(QueryCache::new(lifted_cache_bytes)),
            changes: Arc::new(RwLock::new(ChangeIndex::new(revision))),
            registry,
        }
    }

    pub(crate) fn lookup_lifted_erased(
        &self,
        project: &Project,
        function: FunctionId,
        form: &IlFormId,
        lookup: IlLookup,
    ) -> Result<Option<Arc<dyn Any + Send + Sync>>, ProjectError> {
        if lookup == IlLookup::Current {
            match self.cache.lifted_erased(function, form) {
                CacheLookup::Hit(cached) => return Ok(Some(cached)),
                CacheLookup::Absent => return Ok(None),
                CacheLookup::Miss => {}
            }
        }

        let ir = match project.lifted_erased(&self.registry, function, form) {
            Ok(ir) => ir.map(Arc::<dyn Any + Send + Sync>::from),
            Err(ProjectError::Il(IlError::StaleArtefact { .. })) => None,
            Err(error) => return Err(error),
        };
        if lookup == IlLookup::Current {
            let registration = self
                .registry
                .form(form)
                .ok_or_else(|| IlError::unregistered_form(form.clone()))?;
            let size = match ir.as_ref() {
                Some(ir) => (registration.size())(ir.as_ref())?,
                None => 0,
            };
            self.cache
                .insert_lifted_erased(function, form, ir.clone(), size);
        }
        Ok(ir)
    }

    pub(crate) fn insert_lifted_erased(
        &self,
        function: FunctionId,
        form: &IlFormId,
        ir: Arc<dyn Any + Send + Sync>,
    ) -> Result<(), ProjectError> {
        let registration = self
            .registry
            .form(form)
            .ok_or_else(|| IlError::unregistered_form(form.clone()))?;
        let size = (registration.size())(ir.as_ref())?;
        self.cache
            .insert_lifted_erased(function, form, Some(ir), size);
        Ok(())
    }

    pub(crate) fn reader(&self, intake: Sender<Intake>) -> QueryReader {
        QueryReader::new(
            self.active.clone(),
            self.publication_lock.clone(),
            self.project.clone(),
            self.cache.clone(),
            self.changes.clone(),
            Some(intake),
            self.registry.clone(),
        )
    }

    pub(crate) fn begin_publication(&self) -> QueryPublicationGuard {
        self.publication_lock.write_arc()
    }

    pub(crate) fn apply_changes(&self, changes: &ChangeSet) -> bool {
        let collapsed = self.changes.write().apply(changes);

        for record in changes.records() {
            match record {
                ChangeRecord::FunctionAdded { entry, .. }
                | ChangeRecord::FunctionChanged { entry, .. }
                | ChangeRecord::FunctionRemoved { entry, .. } => {
                    self.cache.remove_flow_targets(*entry);
                }
                ChangeRecord::LiftedMaterialised { function, form }
                | ChangeRecord::LiftedRemoved { function, form } => {
                    self.cache.remove_lifted(*function, form);
                }
                ChangeRecord::Resynchronise { .. } => self.cache.clear(),
                _ => {}
            }

            if record.affects_lifted_inputs() {
                self.cache.clear_lifted();
            }
        }

        collapsed
    }

    pub(crate) fn mark_dead(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl Drop for QueryEngine {
    fn drop(&mut self) {
        self.mark_dead();
    }
}

#[cfg(test)]
mod test {
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::RwLock;

    use super::*;
    use crate::il::common::{
        IlArtefact, IlBlockId, IlDominance, IlGraph, IlIndexRange, IlMetadata, IlSourceSpan,
        IlValueId, PersistableIl,
    };
    use crate::il::ecode::{ECodeBuilder, ECodeIr, ECodeLiveness, ECodeUses};
    use crate::il::pcode::{PCodeBuilder, PCodeIr};
    use crate::ir::{
        Address, AddressRange, AddressRangeSet, FunctionId, IncompleteCodeBlock,
        IncompleteFunction, RawAddress, ReferenceKind, ReferenceOrigin, ReferenceTarget,
    };
    use crate::loader::Loader;
    use crate::project::{
        ChangeKinds, ChangeRecord, ChangeSet, FunctionChangeKind, ProjectTransaction,
    };
    use crate::queries::{Dependency, QueryError, QueryReader, Term};
    use crate::storage::segments::mapping::SegmentMappingId;
    use crate::storage::segments::space::AddressSpaceId;
    use crate::types::Revision;

    struct PublishedIl {
        pcode: PCodeIr,
        ecode: ECodeIr,
    }

    struct Fixture {
        project: Arc<RwLock<Project>>,
        queries: QueryEngine,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let loader = Loader::from_file("tests/ls.elf")?;
            let project = Arc::new(RwLock::new(Project::new_transient(&loader)?));
            let queries = QueryEngine::new(
                project.clone(),
                IlRegistry::standard().clone(),
                64 * 1024 * 1024,
            );
            Ok(Self { project, queries })
        }

        fn reader(&self) -> QueryReader {
            QueryReader::new(
                self.queries.active.clone(),
                self.queries.publication_lock.clone(),
                self.queries.project.clone(),
                self.queries.cache.clone(),
                self.queries.changes.clone(),
                None,
                self.queries.registry.clone(),
            )
        }

        fn next_revision(&self) -> Revision {
            self.project.read().revision().next()
        }

        fn commit_with<T>(
            &self,
            mutate: impl FnOnce(&mut ProjectTransaction<'_>) -> Result<T, ProjectError>,
        ) -> Result<T, Box<dyn Error>> {
            let (changes, value) = {
                let mut project = self.project.write();
                let mut transaction = project.transaction("query fixture");
                let value = match mutate(&mut transaction) {
                    Ok(value) => value,
                    Err(error) => {
                        drop(transaction);
                        return Err(error.into());
                    }
                };
                (transaction.commit()?, value)
            };
            self.queries.apply_changes(&changes);
            Ok(value)
        }

        fn commit_function(&self, function: IncompleteFunction) -> Result<(), Box<dyn Error>> {
            self.commit_function_with_id(function).map(drop)
        }

        fn commit_function_with_id(
            &self,
            function: IncompleteFunction,
        ) -> Result<FunctionId, Box<dyn Error>> {
            self.commit_with(|transaction| transaction.add_function(function))
        }

        fn remove_function(&self, entry: Address) -> Result<(), Box<dyn Error>> {
            self.commit_with(|transaction| {
                transaction.remove_function(entry, ReferenceOrigin::Derived)
            })
            .map(drop)
        }

        fn replace_lifted<T>(&self, ir: &mut T) -> Result<(), Box<dyn Error>>
        where
            T: Clone + PersistableIl,
        {
            ir.metadata_mut()
                .set_input_revision(self.project.read().semantic_revision());
            self.commit_with(|transaction| transaction.replace_lifted(ir.clone()))
        }

        fn apply(&self, changes: &ChangeSet) {
            self.queries.apply_changes(changes);
        }

        fn function_at(entry: Address) -> IncompleteFunction {
            Self::function_with_size(entry, 1)
        }

        fn function_with_size(entry: Address, size: usize) -> IncompleteFunction {
            let mut function = IncompleteFunction::new(entry);
            function.push_block(
                IncompleteCodeBlock::try_new(entry, size, Vec::new(), Default::default())
                    .expect("test block size must be valid"),
            );
            function
        }

        fn pcode_with_span(function: FunctionId, tag: u8, count: u32) -> PCodeIr {
            let mut builder = PCodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default());

            builder.set_source_spans(vec![IlSourceSpan::new(
                IlIndexRange::EMPTY,
                Address::new(AddressSpaceId::new(1), u64::from(tag)),
                u32::from(tag),
                count,
            )]);

            builder.build().expect("test pcode ir should build")
        }

        fn pcode_for(function: FunctionId) -> PCodeIr {
            PCodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default())
                .build()
                .expect("empty pcode ir should build")
        }

        fn ecode_for(function: FunctionId) -> ECodeIr {
            ECodeBuilder::new(IlMetadata::new(function, 0), IlGraph::default())
                .build()
                .expect("empty ecode ir should build")
        }

        fn replace_lifted_chain(
            &self,
            function: FunctionId,
        ) -> Result<PublishedIl, Box<dyn Error>> {
            let mut pcode = Self::pcode_for(function);
            let mut ecode = Self::ecode_for(function);

            self.replace_lifted(&mut pcode)?;
            self.replace_lifted(&mut ecode)?;

            Ok(PublishedIl { pcode, ecode })
        }
    }

    #[test]
    fn test_query_reader_reads_materialised_pcode() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let mut ir = Fixture::pcode_with_span(FunctionId::default(), 7, 3);

        fixture.replace_lifted(&mut ir)?;

        let read = fixture
            .reader()
            .pcode(FunctionId::default())?
            .expect("pcode should be visible to query reader");

        assert_eq!(read.source_spans(), ir.source_spans());
        Ok(())
    }

    #[test]
    fn test_reader_without_intake_declines_generation() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;

        assert!(fixture.reader().pcode(function)?.is_none());

        Ok(())
    }

    #[test]
    fn test_query_reader_reuses_lifted_reads() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;
        let mut ir = Fixture::pcode_for(function);
        fixture.replace_lifted(&mut ir)?;
        fixture.queries.cache.clear_lifted();

        let reader = fixture.reader();
        let first = reader.pcode(function)?.expect("pcode should be visible");
        let second = reader
            .pcode(function)?
            .expect("cached pcode should be visible");
        assert!(Arc::ptr_eq(&first, &second));

        fixture.commit_function(Fixture::function_with_size(entry, 2))?;
        assert!(reader.pcode(function)?.is_none());

        Ok(())
    }

    #[test]
    fn test_query_reader_lifted_snapshot_survives_invalidation() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);
        let function = fixture.commit_function_with_id(Fixture::function_at(entry))?;
        let mut ir = Fixture::pcode_for(function);

        fixture.replace_lifted(&mut ir)?;

        let reader = fixture.reader();
        let snapshot = reader
            .pcode(function)?
            .expect("pcode should be visible to query reader");

        fixture.commit_function(Fixture::function_with_size(entry, 2))?;

        assert!(reader.pcode(function)?.is_none());
        assert_eq!(snapshot.as_ref(), &ir);

        Ok(())
    }

    #[test]
    fn test_query_reader_reads_all_lifted_levels() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let function = FunctionId::default();

        let materialised = fixture.replace_lifted_chain(function)?;

        let reader = fixture.reader();
        let pcode = reader
            .pcode(function)?
            .expect("pcode should be visible to query reader");
        let ecode = reader
            .ecode(function)?
            .expect("ecode should be visible to query reader");
        assert_eq!(pcode.as_ref(), &materialised.pcode);
        assert_eq!(ecode.as_ref(), &materialised.ecode);
        Ok(())
    }

    #[test]
    fn test_query_reader_reads_ssa_derived_tables() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let function = FunctionId::default();

        fixture.replace_lifted_chain(function)?;

        let reader = fixture.reader();
        let ir = reader
            .ecode(function)?
            .expect("ECode IR should be available");
        let uses = ir.analyse::<ECodeUses>();
        let dominance = ir.analyse::<IlDominance>();
        let frontiers = dominance.frontiers(ir.graph().blocks(), ir.graph().successors());
        let liveness = ir.analyse::<ECodeLiveness>();

        let value = IlValueId::try_from_index(0)?;
        let block = IlBlockId::try_from_index(0)?;

        assert!(uses.uses_for(value).is_empty());
        assert!(!dominance.is_reachable(block));
        assert!(frontiers.frontier_for(block).is_empty());
        assert!(liveness.live_in(block).is_empty());
        assert!(liveness.live_out(block).is_empty());
        Ok(())
    }

    #[test]
    fn test_flow_graph_cache_is_exact_per_function() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let edited = Address::from(0x1_0000_0000u64);
        let same_window = Address::new(edited.space(), edited.offset() + 0x10);
        let distant = Address::from(0x9_0000_0000u64);

        fixture.commit_function(Fixture::function_at(edited))?;
        fixture.commit_function(Fixture::function_at(same_window))?;
        fixture.commit_function(Fixture::function_at(distant))?;

        let reader = fixture.reader();
        let edited_before = reader.flow_targets(edited)?.ok_or("edited missing")?;
        let neighbour_before = reader
            .flow_targets(same_window)?
            .ok_or("neighbour missing")?;
        let distant_before = reader.flow_targets(distant)?.ok_or("distant missing")?;

        fixture.commit_function(Fixture::function_with_size(edited, 2))?;

        let edited_after = reader.flow_targets(edited)?.ok_or("edited missing after")?;
        let neighbour_after = reader
            .flow_targets(same_window)?
            .ok_or("neighbour missing after")?;
        let distant_after = reader
            .flow_targets(distant)?
            .ok_or("distant missing after")?;

        assert!(!Arc::ptr_eq(&edited_before, &edited_after));
        assert!(Arc::ptr_eq(&neighbour_before, &neighbour_after));
        assert!(Arc::ptr_eq(&distant_before, &distant_after));

        Ok(())
    }

    #[test]
    fn test_flow_graph_cache_invalidation_property() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entries = (0..8u64)
            .map(|index| Address::from(0x1_0000_0000u64 + index * 0x10))
            .collect::<Vec<_>>();

        for entry in &entries {
            fixture.commit_function(Fixture::function_at(*entry))?;
        }

        let reader = fixture.reader();

        for edited_index in 0..entries.len() {
            let before = entries
                .iter()
                .map(|entry| Ok(reader.flow_targets(*entry)?.ok_or("function missing")?))
                .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

            fixture.commit_function(Fixture::function_with_size(
                entries[edited_index],
                2 + edited_index,
            ))?;

            for (index, entry) in entries.iter().enumerate() {
                let after = reader
                    .flow_targets(*entry)?
                    .ok_or("function missing after")?;
                let stable = Arc::ptr_eq(&before[index], &after);
                assert_eq!(
                    stable,
                    index != edited_index,
                    "only the edited function's cached graph may be invalidated"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_function_removal_invalidates_cached_flow_graph() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        fixture.commit_function(Fixture::function_at(entry))?;

        let reader = fixture.reader();
        assert!(reader.flow_targets(entry)?.is_some());

        fixture.remove_function(entry)?;

        assert!(reader.flow_targets(entry)?.is_none());

        Ok(())
    }

    #[test]
    fn test_function_add_invalidates_cached_absence() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        let reader = fixture.reader();
        assert!(reader.flow_targets(entry)?.is_none());
        assert!(reader.flow_targets(entry)?.is_none());

        fixture.commit_function(Fixture::function_at(entry))?;

        assert!(reader.flow_targets(entry)?.is_some());

        Ok(())
    }

    #[test]
    fn test_byte_write_leaves_flow_graph_cached() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        fixture.commit_function(Fixture::function_at(entry))?;

        let reader = fixture.reader();
        let before = reader.flow_targets(entry)?.ok_or("function missing")?;

        let revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            revision,
            [ChangeRecord::BytesWritten {
                range: AddressRange::new(entry.space(), entry.raw_address(), entry.raw_address()),
            }],
        ));

        let after = reader
            .flow_targets(entry)?
            .ok_or("function missing after write")?;

        assert!(Arc::ptr_eq(&before, &after));

        Ok(())
    }

    #[test]
    fn test_cache_is_pure_derived_state() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let entry = Address::from(0x1_0000_0000u64);

        fixture.commit_function(Fixture::function_with_size(entry, 4))?;

        let reader = fixture.reader();
        let before = reader.flow_targets(entry)?.ok_or("function missing")?;

        fixture.queries.cache.clear();

        let after = reader
            .flow_targets(entry)?
            .ok_or("function missing after clear")?;

        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(before.targets(), after.targets());

        Ok(())
    }

    #[test]
    fn test_latest_change_tracks_region_and_kinds() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let inside = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x1000u64),
            RawAddress::from(0x1fffu64),
        );
        let outside = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x8000u64),
            RawAddress::from(0x8fffu64),
        );
        let mut region = AddressRangeSet::new();
        region.insert_range(inside);

        let baseline = reader.revision()?;
        assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);

        let outside_revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            outside_revision,
            [ChangeRecord::BytesWritten { range: outside }],
        ));
        assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);

        let inside_revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            inside_revision,
            [ChangeRecord::BytesWritten { range: inside }],
        ));
        assert!(reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);
        assert_eq!(
            reader.latest_change(ChangeKinds::BYTES_WRITTEN, &region)?,
            inside_revision
        );
        assert!(!reader.changed_since(baseline, ChangeKinds::FUNCTIONS, &region)?);

        Ok(())
    }

    #[test]
    fn test_reference_change_is_observable_from_both_endpoints() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let from = Address::new(AddressSpaceId::from(0u8), 0x1000u64);
        let to = Address::new(AddressSpaceId::from(0u8), 0x8000u64);
        let disjoint = Address::new(AddressSpaceId::from(0u8), 0x9000u64);

        let baseline = reader.revision()?;
        let revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            revision,
            [ChangeRecord::ReferenceAdded {
                from,
                target: ReferenceTarget::from(to),
                kind: ReferenceKind::Flow,
            }],
        ));

        for observed in [from, to] {
            let mut region = AddressRangeSet::new();
            region.insert_range(AddressRange::point(observed));
            assert!(reader.changed_since(baseline, ChangeKinds::REFERENCES, &region)?);
        }

        let mut disjoint_region = AddressRangeSet::new();
        disjoint_region.insert_range(AddressRange::point(disjoint));
        assert!(!reader.changed_since(baseline, ChangeKinds::REFERENCES, &disjoint_region)?);

        Ok(())
    }

    #[test]
    fn test_latest_change_kinds_mask_selects_groups() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let range = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x1000u64),
            RawAddress::from(0x1fffu64),
        );
        let mut region = AddressRangeSet::new();
        region.insert_range(range);

        let baseline = reader.revision()?;
        let mapped_revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            mapped_revision,
            [ChangeRecord::SegmentMapped {
                mapping: SegmentMappingId::new(0),
                range,
            }],
        ));

        assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);
        assert!(reader.changed_since(baseline, ChangeKinds::SEGMENTS, &region)?);
        assert!(reader.changed_since(
            baseline,
            ChangeKinds::BYTES_WRITTEN | ChangeKinds::SEGMENTS,
            &region
        )?);

        Ok(())
    }

    #[test]
    fn test_region_less_changes_are_observable() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let mut region = AddressRangeSet::new();
        region.insert_range(AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x1000u64),
            RawAddress::from(0x1fffu64),
        ));
        let baseline = reader.revision()?;
        let created = Revision::new(baseline.value() + 1);
        let changed = Revision::new(baseline.value() + 2);
        let space = Revision::new(baseline.value() + 3);

        fixture.apply(&ChangeSet::with_records(
            created,
            [ChangeRecord::SegmentMappingCreated {
                mapping: SegmentMappingId::new(0),
            }],
        ));
        assert!(reader.changed_since(baseline, ChangeKinds::SEGMENT_MAPPING_CREATED, &region)?);
        assert!(reader.changed_since(baseline, ChangeKinds::SEGMENTS, &region)?);
        assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &region)?);

        fixture.apply(&ChangeSet::with_records(
            changed,
            [ChangeRecord::SegmentMappingChanged {
                mapping: SegmentMappingId::new(0),
            }],
        ));
        assert!(reader.changed_since(created, ChangeKinds::SEGMENT_MAPPING_CHANGED, &region)?);

        fixture.apply(&ChangeSet::with_records(
            space,
            [ChangeRecord::SpaceCreated {
                space: AddressSpaceId::from(7u8),
            }],
        ));
        assert!(reader.changed_since(changed, ChangeKinds::SPACE_CREATED, &region)?);

        Ok(())
    }

    #[test]
    fn test_region_bearing_precision_survives_region_less_kinds() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let touched = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x1000u64),
            RawAddress::from(0x1fffu64),
        );
        let mut disjoint = AddressRangeSet::new();
        disjoint.insert_range(AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x8000u64),
            RawAddress::from(0x8fffu64),
        ));

        let baseline = reader.revision()?;
        let write = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            write,
            [ChangeRecord::BytesWritten { range: touched }],
        ));

        assert!(!reader.changed_since(baseline, ChangeKinds::BYTES_WRITTEN, &disjoint)?);

        Ok(())
    }

    #[test]
    fn test_resynchronisation_marks_every_region_changed() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let baseline = reader.revision()?;
        let resynchronised_revision = fixture.next_revision();
        fixture.apply(&ChangeSet::with_records(
            resynchronised_revision,
            [ChangeRecord::Resynchronise {
                to: resynchronised_revision,
            }],
        ));

        let region = AddressRangeSet::new();
        assert!(reader.changed_since(baseline, ChangeKinds::all(), &region)?);
        assert!(reader.changed_since(baseline, ChangeKinds::FUNCTIONS, &region)?);

        Ok(())
    }

    #[test]
    fn test_term_recomputes_only_on_dependency_change() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let inside = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x1000u64),
            RawAddress::from(0x1fffu64),
        );
        let outside = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x8000u64),
            RawAddress::from(0x8fffu64),
        );
        let mut region = AddressRangeSet::new();
        region.insert_range(inside);

        let calls = AtomicUsize::new(0);
        let mut term = Term::new(Dependency::on(ChangeKinds::BYTES_WRITTEN).within(region));

        let first = *term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second = *term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(first, second);

        let base = reader.revision()?;
        fixture.apply(&ChangeSet::with_records(
            Revision::new(base.value() + 1),
            [ChangeRecord::BytesWritten { range: outside }],
        ));
        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        fixture.apply(&ChangeSet::with_records(
            Revision::new(base.value() + 2),
            [ChangeRecord::BytesWritten { range: inside }],
        ));
        let refreshed = *term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_ne!(first, refreshed);

        Ok(())
    }

    #[test]
    fn test_term_values_need_not_be_clone() -> Result<(), Box<dyn Error>> {
        struct Value(usize);

        let fixture = Fixture::new()?;
        let reader = fixture.reader();
        let calls = AtomicUsize::new(0);
        let mut term = Term::new(Dependency::on(ChangeKinds::FUNCTIONS));

        let value = term.evaluate(&reader, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Value(42))
        })?;
        assert_eq!(value.0, 42);

        let value = term.evaluate(&reader, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Value(0))
        })?;
        assert_eq!(value.0, 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn test_term_composes_across_inputs() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let functions = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x1000u64),
            RawAddress::from(0x1fffu64),
        );
        let bytes = AddressRange::new(
            AddressSpaceId::from(0u8),
            RawAddress::from(0x4000u64),
            RawAddress::from(0x4fffu64),
        );
        let mut function_region = AddressRangeSet::new();
        function_region.insert_range(functions);
        let mut byte_region = AddressRangeSet::new();
        byte_region.insert_range(bytes);

        let calls = AtomicUsize::new(0);
        let mut term = Term::new(
            Dependency::on(ChangeKinds::FUNCTIONS)
                .within(function_region)
                .and(Dependency::on(ChangeKinds::BYTES_WRITTEN).within(byte_region)),
        );

        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let base = reader.revision()?;
        let mut function_coverage = AddressRangeSet::new();
        function_coverage.insert_range(functions);
        fixture.apply(&ChangeSet::with_records(
            Revision::new(base.value() + 1),
            [ChangeRecord::FunctionChanged {
                entry: functions.start_address(),
                kind: FunctionChangeKind::Body,
                coverage: function_coverage,
            }],
        ));
        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        fixture.apply(&ChangeSet::with_records(
            Revision::new(base.value() + 2),
            [ChangeRecord::BytesWritten { range: bytes }],
        ));
        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        fixture.apply(&ChangeSet::with_records(
            Revision::new(base.value() + 3),
            [ChangeRecord::BytesWritten {
                range: AddressRange::new(
                    AddressSpaceId::from(0u8),
                    RawAddress::from(0x9000u64),
                    RawAddress::from(0x9fffu64),
                ),
            }],
        ));
        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        Ok(())
    }

    #[test]
    fn a_term_rejects_undeclared_observed_reads() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();
        let mut term = Term::new(Dependency::on(ChangeKinds::FUNCTIONS));

        let error = term
            .evaluate(&reader, |view| {
                let _ = view.symbols();
                Ok(())
            })
            .expect_err("symbol reads must exceed a functions-only dependency");

        assert!(matches!(
            error,
            QueryError::UndeclaredDependency(kinds) if kinds.contains(ChangeKinds::SYMBOLS)
        ));
        Ok(())
    }

    #[test]
    fn test_term_region_less_dependency() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let reader = fixture.reader();

        let calls = AtomicUsize::new(0);
        let mut term = Term::new(Dependency::on(ChangeKinds::SEGMENT_MAPPING_CREATED));

        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let base = reader.revision()?;
        fixture.apply(&ChangeSet::with_records(
            Revision::new(base.value() + 1),
            [ChangeRecord::SegmentMappingCreated {
                mapping: SegmentMappingId::new(0),
            }],
        ));
        term.evaluate(&reader, |_| Ok(calls.fetch_add(1, Ordering::SeqCst)))?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        Ok(())
    }
}
