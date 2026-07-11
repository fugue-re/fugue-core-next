#![cfg(feature = "static-lifters")]

use std::collections::BTreeSet;
use std::io;
use std::time::Duration;

use fallible_iterator::FallibleIterator;
use fugue_core::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::Arch;
use fugue_core::engine::change::ChangeRecord;
use fugue_core::engine::{AnalysisEngine, MappingMetadataUpdate};
use fugue_core::ir::{
    Address, Endian, RawAddress, SegmentProperties, SymbolEntry, SymbolIndex, SymbolProperties,
    SymbolTableSelector,
};
use fugue_core::lifter::resolve_language;
use fugue_core::loader::{
    ImageAddress, ImageBacking, ImageBank, ImageBankHandle, ImageLayout, ImageSegment,
    ImageSegmentContents, ImageSegmentContentsIterator, ImageSegmentIterator, ImageSpace,
    ImageSpaceHandle, Loadable, LoadableAnalysers, LoadableMetadata, Loader, LoaderError,
};
use fugue_core::project::Project;
use fugue_core::queries::QueryError;
use fugue_core::storage::segments::DEFAULT_SPACE_ID;
use fugue_core::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingKind, SegmentMappingProvenance,
};
use fugue_core::types::AttributeMap;

#[test]
fn test_engine_startup_reaches_imperative_entry() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;

    let mut imperative = Project::new_transient(&loader)?;
    let Some(entry) = imperative.entry() else {
        return Err(io::Error::other("fixture entry missing").into());
    };
    let mut recovery = loader.analysers().function_recovery()?;
    recovery.add_candidate(entry);
    AnalysisPass::analyse(&mut recovery, &mut imperative)?;

    let imperative_functions = imperative.functions().addresses().collect::<BTreeSet<_>>();
    assert!(imperative_functions.contains(&entry));

    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    let changes = engine.subscribe(4096)?;
    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let mut cursor = None;
    let mut engine_functions = BTreeSet::new();
    loop {
        let page = reader.function_page(cursor, 128)?;
        engine_functions.extend(page.entries().iter().copied());

        let Some(next_cursor) = page.next_cursor().copied() else {
            break;
        };
        cursor = Some(next_cursor);
    }
    let mut journal_functions = BTreeSet::new();

    for changes in changes.try_iter() {
        for record in changes.records() {
            match record {
                ChangeRecord::FunctionAdded { entry } => {
                    journal_functions.insert(*entry);
                }
                ChangeRecord::FunctionRemoved { entry } => {
                    journal_functions.remove(entry);
                }
                ChangeRecord::Restored { .. } => {
                    return Err(io::Error::other("subscriber was forced to resync").into());
                }
                _ => {}
            }
        }
    }

    let flow_graph = reader
        .flow_graph(entry)?
        .ok_or_else(|| io::Error::other("fixture entry flow graph missing"))?;
    let expected_callees = flow_graph
        .targets()
        .iter()
        .filter(|target| target.kind().is_call())
        .map(|target| target.to())
        .collect::<BTreeSet<_>>();
    let callees = reader
        .callees_of(entry, None, 4096)?
        .entries()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let call_edges = reader
        .call_edges(None, 4096)?
        .entries()
        .iter()
        .filter(|edge| edge.caller() == entry)
        .map(|edge| edge.callee())
        .collect::<BTreeSet<_>>();

    assert_eq!(callees, expected_callees);
    assert_eq!(call_edges, expected_callees);
    assert_eq!(engine_functions, imperative_functions);
    assert_eq!(journal_functions, engine_functions);

    Ok(())
}

#[test]
fn test_query_reader_reports_stopped_after_engine_drop() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;
    let reader = engine.query_reader()?;

    engine.wait_until_idle()?;
    assert!(reader.revision().is_ok());

    drop(engine);

    assert_eq!(reader.revision(), Err(QueryError::Stopped));

    Ok(())
}

#[test]
fn test_engine_startup_uses_segment_function_hints() -> Result<(), Box<dyn std::error::Error>> {
    struct HintLoader {
        arch: Arch,
        attributes: AttributeMap,
        layout: ImageLayout,
        metadata: LoadableMetadata,
    }

    impl Loadable for HintLoader {
        fn attributes(&self) -> &AttributeMap {
            &self.attributes
        }

        fn attributes_mut(&mut self) -> &mut AttributeMap {
            &mut self.attributes
        }

        fn metadata(&self) -> &LoadableMetadata {
            &self.metadata
        }

        fn architecture(&self) -> Arch {
            self.arch.clone()
        }

        fn image_layout(&self) -> &ImageLayout {
            &self.layout
        }

        fn image_segments<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
            let segment = ImageSegment::new(
                "hint",
                ImageAddress::in_default_space(0x1000u64),
                1,
                SegmentProperties::PERM_ALL,
            )
            .with_backing(ImageBacking::in_default_bank(0u64));

            Box::new(fallible_iterator::convert(std::iter::once(Ok(segment))))
                as ImageSegmentIterator<'a>
        }

        fn image_contents<'a>(
            &'a self,
        ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a
        {
            let mut contents = ImageSegmentContents::new(0x1000u64, Endian::Little, vec![0xc3u8]);
            contents.add_function_hint(0x1000u64);

            Box::new(fallible_iterator::convert(std::iter::once(Ok(contents))))
                as ImageSegmentContentsIterator<'a>
        }
    }

    let layout = ImageLayout::new(
        vec![ImageBank::new(
            ImageBankHandle::default(),
            RawAddress::from(0x1000u64)..=RawAddress::from(0x1000u64),
        )],
        vec![ImageSpace::base(ImageSpaceHandle::default())],
    );
    let loader = HintLoader {
        arch: Arch::new(resolve_language("x86:LE:64")?),
        attributes: AttributeMap::new(),
        layout,
        metadata: LoadableMetadata::new([0xc3u8], "hint-loader"),
    };
    let project = Project::new_transient(&loader)?;

    assert!(project.entry().is_none());

    let hint = Address::in_default_space(0x1000u64);
    let engine = AnalysisEngine::new(project)?;
    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;

    assert!(reader.function_page(None, 16)?.entries().contains(&hint));

    Ok(())
}

#[test]
fn test_function_recovery_cancel_before_seeding_leaves_project_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;
    let revision = project.revision();
    let mut recovery = loader.analysers().function_recovery()?;
    let cancellation = recovery.cancellation_token();

    cancellation.cancel();
    recovery.set_cancellation_token(cancellation);

    let error = AnalysisPass::analyse(&mut recovery, &mut project)
        .expect_err("cancelled recovery should fail");

    assert!(matches!(error, AnalysisError::Cancelled(_)));
    assert_eq!(project.revision(), revision);
    assert!(project.functions().is_empty());

    Ok(())
}

#[test]
fn test_engine_write_bytes_publishes_change() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable())
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let revision = reader.revision()?;
    let changes = engine.subscribe(16)?;

    let written = engine.write_bytes(address, [0xcc])?;

    assert!(written.revision() > revision);
    assert!(written.records().contains(&ChangeRecord::BytesWritten {
        space: address.space(),
        range: (address.raw_address(), address.raw_address()),
    }));

    let delivered = changes.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(&*delivered, &written);

    Ok(())
}

#[test]
fn test_engine_partial_write_publishes_written_range() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .filter(|view| view.properties().is_writable())
        .max_by_key(|view| view.last())
        .map(|view| view.last())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let changes = engine.subscribe(16)?;

    assert!(engine.write_bytes(address, [0xcc, 0xdd]).is_err());

    let delivered = changes.recv_timeout(Duration::from_secs(1))?;
    assert!(delivered.records().contains(&ChangeRecord::BytesWritten {
        space: address.space(),
        range: (address.raw_address(), address.raw_address()),
    }));

    Ok(())
}

#[test]
fn test_engine_symbol_edits_publish_changes() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let revision = reader.revision()?;
    let changes = engine.subscribe(16)?;
    let index = SymbolIndex::new(SymbolTableSelector::new(250), 0);
    let symbol = SymbolEntry::new(
        entry,
        "engine_symbol_edit",
        SymbolProperties::LOCAL | SymbolProperties::FUNCTION,
    );

    let inserted = engine.insert_symbol(index, symbol.clone())?;

    assert!(inserted.revision() > revision);
    assert!(inserted.records().contains(&ChangeRecord::SymbolAdded {
        address: entry,
        symbol: symbol.symbol(),
    }));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &inserted);
    assert!(
        reader
            .symbols_at(entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol.symbol())
    );

    let removed = engine.remove_symbol(index)?;

    assert!(removed.revision() > inserted.revision());
    assert!(removed.records().contains(&ChangeRecord::SymbolRemoved {
        address: entry,
        symbol: symbol.symbol(),
    }));
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &removed);
    assert!(
        !reader
            .symbols_at(entry, None, 16)?
            .entries()
            .iter()
            .any(|record| record.symbol() == symbol.symbol())
    );

    Ok(())
}

#[test]
fn test_engine_remove_function_updates_queries() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let entry = project
        .entry()
        .ok_or_else(|| io::Error::other("fixture entry missing"))?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let changes = engine.subscribe(16)?;
    assert!(reader.flow_graph(entry)?.is_some());

    let removed = engine.remove_function(entry)?;

    assert!(
        removed
            .records()
            .contains(&ChangeRecord::FunctionRemoved { entry })
    );
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &removed);
    assert!(reader.flow_graph(entry)?.is_none());
    assert!(!reader.function_page(None, 4096)?.entries().contains(&entry));

    let mut function = PartialFunction::new(entry);
    function.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        Default::default(),
    ));
    let added = engine.add_function(function)?;

    assert!(
        added
            .records()
            .contains(&ChangeRecord::FunctionAdded { entry })
    );
    assert_eq!(&*changes.recv_timeout(Duration::from_secs(1))?, &added);
    assert!(reader.flow_graph(entry)?.is_some());
    assert!(reader.function_page(None, 4096)?.entries().contains(&entry));

    Ok(())
}

#[test]
fn test_engine_mapping_edits_publish_changes() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let view = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.size() > 1)
        .ok_or_else(|| io::Error::other("fixture mapping missing"))?;
    let mapping_id = view.mapping_ref().mapping_id();
    let mapping = project
        .segments()
        .mapping(mapping_id)
        .ok_or_else(|| io::Error::other("fixture mapping metadata missing"))?;
    let mapping_offset = mapping.offset();
    let mapping_properties = mapping.properties();
    let provider_id = mapping.provider_id();
    let old_start = mapping.start();
    let old_size = mapping.size();
    let old_range = (mapping.start().raw_address(), mapping.last().raw_address());
    let new_start = old_start
        .checked_add(old_size + 0x1000)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely remapped"))?;
    let remapped_last = new_start
        .checked_add(old_size - 1)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely remapped"))?;
    let remapped_range = (new_start.raw_address(), remapped_last.raw_address());
    let resized_size = old_size - 1;
    let resized_last = new_start
        .checked_add(resized_size - 1)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely resized"))?;
    let resized_range = (new_start.raw_address(), resized_last.raw_address());
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    let reader = engine.query_reader()?;
    let changes = engine.subscribe(16)?;
    assert!(
        reader
            .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == mapping_id)
    );

    let created_start = old_start
        .checked_add(old_size + 0x2000)
        .ok_or_else(|| io::Error::other("fixture mapping cannot be safely duplicated"))?;
    let created = engine.create_mapping_from_builder(
        SegmentMappingBuilder::new(created_start, 1, mapping_offset, provider_id)
            .with_properties(mapping_properties)
            .with_name("engine-created"),
    )?;
    let created_id = created.mapping();

    assert!(
        created
            .changes()
            .records()
            .contains(&ChangeRecord::SegmentMappingCreated {
                mapping: created_id
            })
    );
    assert!(
        !reader
            .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == created_id)
    );

    let created_space = engine.create_space()?;
    let extra_space = created_space.space();

    assert!(
        created_space
            .changes()
            .records()
            .contains(&ChangeRecord::SpaceCreated { space: extra_space })
    );

    let placed = engine.add_mapping_to_space(extra_space, created_id)?;

    assert!(placed.records().contains(&ChangeRecord::SegmentMapped {
        mapping: created_id,
        space: extra_space,
        range: (created_start.raw_address(), created_start.raw_address()),
    }));
    assert!(
        reader
            .mapping_page(extra_space, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == created_id)
    );

    let metadata = engine.update_mapping_metadata(
        MappingMetadataUpdate::new(created_id)
            .with_kind(SegmentMappingKind::Mmap)
            .with_provenance(SegmentMappingProvenance::Synthetic)
            .with_flags(SegmentMappingFlags::PRIVATE),
    )?;

    assert!(
        metadata
            .records()
            .contains(&ChangeRecord::SegmentMappingChanged {
                mapping: created_id
            })
    );

    let remapped = engine.remap_mapping(mapping_id, new_start)?;

    assert!(remapped.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping: mapping_id,
        space: DEFAULT_SPACE_ID,
        range: old_range,
    }));
    assert!(remapped.records().contains(&ChangeRecord::SegmentMapped {
        mapping: mapping_id,
        space: DEFAULT_SPACE_ID,
        range: remapped_range,
    }));
    let mut delivered = false;
    for _ in 0..16 {
        if &*changes.recv_timeout(Duration::from_secs(1))? == &remapped {
            delivered = true;
            break;
        }
    }
    assert!(delivered);
    let remapped_record = reader
        .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
        .entries()
        .iter()
        .find(|record| record.mapping() == mapping_id)
        .copied()
        .ok_or_else(|| io::Error::other("remapped mapping missing"))?;
    assert_eq!(remapped_record.start(), new_start);

    let resized = engine.resize_mapping(mapping_id, resized_size)?;

    assert!(resized.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping: mapping_id,
        space: DEFAULT_SPACE_ID,
        range: remapped_range,
    }));
    assert!(resized.records().contains(&ChangeRecord::SegmentMapped {
        mapping: mapping_id,
        space: DEFAULT_SPACE_ID,
        range: resized_range,
    }));
    let mut delivered = false;
    for _ in 0..16 {
        if &*changes.recv_timeout(Duration::from_secs(1))? == &resized {
            delivered = true;
            break;
        }
    }
    assert!(delivered);
    let resized_record = reader
        .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
        .entries()
        .iter()
        .find(|record| record.mapping() == mapping_id)
        .copied()
        .ok_or_else(|| io::Error::other("resized mapping missing"))?;
    assert_eq!(resized_record.size(), resized_size);

    let removed = engine.remove_mapping(mapping_id)?;

    assert!(removed.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping: mapping_id,
        space: DEFAULT_SPACE_ID,
        range: resized_range,
    }));
    let mut delivered = false;
    for _ in 0..16 {
        if &*changes.recv_timeout(Duration::from_secs(1))? == &removed {
            delivered = true;
            break;
        }
    }
    assert!(delivered);
    assert!(
        !reader
            .mapping_page(DEFAULT_SPACE_ID, None, 4096)?
            .entries()
            .iter()
            .any(|record| record.mapping() == mapping_id)
    );

    Ok(())
}

#[test]
fn test_idle_cancel_does_not_poison_future_work() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let project = Project::new_transient(&loader)?;
    let engine = AnalysisEngine::new(project)?;

    engine.wait_until_idle()?;
    engine.cancel()?;
    engine.wait_until_idle()?;
    engine.save()?;

    assert!(!engine.cancellation_token().is_cancelled());

    Ok(())
}
