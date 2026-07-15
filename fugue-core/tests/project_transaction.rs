use std::io;
use std::path::PathBuf;

use fugue_core::analysis::function::recovery::{PartialCodeBlock, PartialFunction};
use fugue_core::engine::change::{ChangeRecord, FunctionChangeKind};
use fugue_core::il::common::{
    ArtefactDigest, ArtefactHeader, Block, BlockId, BuildStatus, CommonBody, Finish, IlError,
    IrArtefact, IrLevel, PackedRange, RawIrArtefact, SchemaVersion, SourceRun, ValueId,
};
use fugue_core::il::llil::ssa::{LLIL_SSA_SCHEMA_VERSION, SsaBuilder};
use fugue_core::il::llil::{LLIL_SCHEMA_VERSION, LlilBuilder};
use fugue_core::il::pcode::{PCODE_SCHEMA_VERSION, PCodeBody, PCodeBuilder};
use fugue_core::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, RawAddress, Reference, ReferenceKind,
    ReferenceTarget, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::lifter::ContextSet;
use fugue_core::project::{Project, ProjectError};
use fugue_core::storage::segments::DEFAULT_SPACE_ID;
use fugue_core::storage::segments::mapping::SegmentMappingId;
use fugue_core::storage::segments::space::AddressSpaceId;
use fugue_core::types::AttributeMap;
use fugue_core::types::attributes::ATTRIBUTE_LOADER_FORMAT;

struct Fixtures;

impl Fixtures {
    fn binary(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(name)
    }
}

fn writable_address(project: &Project) -> Result<Address, Box<dyn std::error::Error>> {
    project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable())
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
}

fn partial_function(entry: Address, len: usize) -> PartialFunction {
    let mut function = PartialFunction::new(entry);
    function.push_block(PartialCodeBlock::new(
        entry,
        len,
        Vec::new(),
        ContextSet::default(),
    ));

    function
}

fn test_common_body(payload: &[u8]) -> CommonBody {
    let tag = payload.first().copied().unwrap_or_default();
    CommonBody::new(
        Vec::new(),
        Vec::new(),
        vec![SourceRun::new(
            PackedRange::EMPTY,
            Address::new(DEFAULT_SPACE_ID, u64::from(tag)),
            u32::from(tag),
            u32::try_from(payload.len()).expect("test payload length should fit"),
        )],
        Vec::new(),
    )
}

fn single_block_common_body() -> CommonBody {
    CommonBody::new(
        vec![Block::new(
            PackedRange::EMPTY,
            PackedRange::EMPTY,
            Block::ENTRY | Block::EXIT,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn test_ir_artefact(function: FunctionId, level: IrLevel, payload: Vec<u8>) -> RawIrArtefact {
    let common = test_common_body(&payload);
    let status = BuildStatus::new();

    match level {
        IrLevel::PCode => {
            let header = ArtefactHeader::new(function, level, PCODE_SCHEMA_VERSION, 0);
            PCodeBuilder::new(header, common)
                .finish(&status)
                .expect("test PCode artefact should verify")
                .to_raw_artefact()
                .expect("test PCode artefact should encode")
        }
        IrLevel::Llil => {
            let header = ArtefactHeader::new(function, level, LLIL_SCHEMA_VERSION, 0);
            LlilBuilder::new(header, common)
                .finish(&status)
                .expect("test LLIL artefact should verify")
                .to_raw_artefact()
                .expect("test LLIL artefact should encode")
        }
        IrLevel::LlilSsa => {
            let header = ArtefactHeader::new(function, level, LLIL_SSA_SCHEMA_VERSION, 0);
            SsaBuilder::new(header, common)
                .finish(&status)
                .expect("test SSA artefact should verify")
                .to_raw_artefact()
                .expect("test SSA artefact should encode")
        }
        IrLevel::MappedMlil | IrLevel::Mlil => {
            let header = ArtefactHeader::new(function, level, SchemaVersion::new(1), 0);
            RawIrArtefact::new(header, common, payload)
        }
    }
}

fn test_pcode_body(function: FunctionId) -> PCodeBody {
    let header = ArtefactHeader::new(function, IrLevel::PCode, PCODE_SCHEMA_VERSION, 0);
    PCodeBuilder::new(header, CommonBody::default())
        .finish(&BuildStatus::new())
        .expect("empty PCode body should verify")
}

fn single_block_ir_artefact(
    function: FunctionId,
    level: IrLevel,
) -> Result<RawIrArtefact, Box<dyn std::error::Error>> {
    let common = single_block_common_body();
    let status = BuildStatus::new();

    match level {
        IrLevel::PCode => {
            let header = ArtefactHeader::new(function, level, PCODE_SCHEMA_VERSION, 0);
            Ok(PCodeBuilder::new(header, common)
                .finish(&status)?
                .to_raw_artefact()?)
        }
        IrLevel::Llil => {
            let header = ArtefactHeader::new(function, level, LLIL_SCHEMA_VERSION, 0);
            Ok(LlilBuilder::new(header, common)
                .finish(&status)?
                .to_raw_artefact()?)
        }
        IrLevel::LlilSsa => {
            let header = ArtefactHeader::new(function, level, LLIL_SSA_SCHEMA_VERSION, 0);
            Ok(SsaBuilder::new(header, common)
                .finish(&status)?
                .to_raw_artefact()?)
        }
        IrLevel::MappedMlil | IrLevel::Mlil => {
            Err(IlError::artefact_level_unsupported(level).into())
        }
    }
}

fn first_mapping_placement(
    project: &Project,
) -> (AddressSpaceId, SegmentMappingId, (RawAddress, RawAddress)) {
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");

    (space, mapping, range)
}

#[test]
fn test_loadable_fallback_preserves_caller_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let mut attributes = AttributeMap::new();
    attributes.set_attr("caller.custom", "preserved");
    attributes.set_attr(ATTRIBUTE_LOADER_FORMAT, "caller-format");

    let project = Project::from_file_transient_with(Fixtures::binary("ls.elf"), attributes)?;

    assert_eq!(
        project
            .attributes()
            .get_attr::<String>("caller.custom")
            .as_deref(),
        Some("preserved")
    );
    assert_eq!(
        project
            .attributes()
            .get_attr::<String>(ATTRIBUTE_LOADER_FORMAT)
            .as_deref(),
        Some("caller-format")
    );

    Ok(())
}

#[test]
fn test_ir_artefact_publish_remove_and_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let artefact = test_ir_artefact(function, IrLevel::PCode, vec![1, 2, 3]);

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(artefact.clone())?;
        transaction.commit()?
    };

    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactPublished {
                function: FunctionId::default(),
                level: IrLevel::PCode,
            })
    );
    assert_eq!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(artefact.content_digest())
    );

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(test_ir_artefact(
            function,
            IrLevel::PCode,
            vec![4, 5, 6],
        ))?;
        transaction.rollback()?;
    }

    assert_eq!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(artefact.content_digest())
    );

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_ir_artefact(FunctionId::default(), IrLevel::PCode)?);
        transaction.commit()?
    };

    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function: FunctionId::default(),
                level: IrLevel::PCode,
            })
    );
    assert!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::PCode)?
            .is_none()
    );

    Ok(())
}

#[test]
fn test_typed_ir_body_publish_and_read() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let mut body = test_pcode_body(FunctionId::default());

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_body(&mut body)?;
        transaction.commit()?;
    }

    let read = project
        .ir_body::<PCodeBody>(FunctionId::default())?
        .expect("PCode body should be published");

    assert_eq!(read.operations(), body.operations());
    assert_eq!(
        read.header().input_revision(),
        project.semantic_revision().value()
    );

    Ok(())
}

#[test]
fn test_project_reads_llil_ssa_derived_tables() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();

    let pcode = single_block_ir_artefact(function, IrLevel::PCode)?;
    let mut llil = single_block_ir_artefact(function, IrLevel::Llil)?;
    llil.set_parent_digest(pcode.header().content_digest());
    let mut ssa = single_block_ir_artefact(function, IrLevel::LlilSsa)?;
    ssa.set_parent_digest(llil.header().content_digest());

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(pcode)?;
        transaction.publish_ir_artefact(llil)?;
        transaction.publish_ir_artefact(ssa)?;
        transaction.commit()?;
    }

    let entry = BlockId::try_from_index(0)?;
    let value = ValueId::try_from_index(0)?;
    let use_index = project
        .llil_ssa_use_index(function)?
        .expect("SSA use index should be available");
    let dominance = project
        .llil_ssa_dominance(function)?
        .expect("SSA dominance should be available");
    let frontiers = project
        .llil_ssa_dominance_frontiers(function)?
        .expect("SSA dominance frontiers should be available");
    let liveness = project
        .llil_ssa_liveness(function)?
        .expect("SSA liveness should be available");

    assert!(use_index.uses_for(value).is_empty());
    assert!(dominance.dominates(entry, entry));
    assert!(frontiers.frontier(entry).is_empty());
    assert!(liveness.live_in(entry).is_empty());
    assert!(liveness.live_out(entry).is_empty());

    Ok(())
}

#[test]
fn test_ensure_ir_builds_llil_from_pcode() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let mut body = test_pcode_body(function);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_body(&mut body)?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(!transaction.ensure_pcode(function, &BuildStatus::new())?);
        assert!(transaction.ensure_llil(function, &BuildStatus::new())?);
        transaction.commit()?
    };

    assert!(project.llil_body(function)?.is_some());
    let pcode = project
        .ir_artefact(function, IrLevel::PCode)?
        .expect("PCode artefact should be present");
    let llil = project
        .ir_artefact(function, IrLevel::Llil)?
        .expect("LLIL artefact should be present");
    assert_eq!(
        llil.header().parent_digest(),
        pcode.header().content_digest()
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactPublished {
                function,
                level: IrLevel::Llil,
            })
    );

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(!transaction.ensure_llil(function, &BuildStatus::new())?);
        transaction.commit()?
    };

    assert!(changes.records().is_empty());

    Ok(())
}

#[test]
fn test_ensure_ir_builds_ssa_through_llil() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let mut body = test_pcode_body(function);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_body(&mut body)?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.ensure_llil_ssa(function, &BuildStatus::new())?);
        transaction.commit()?
    };

    assert!(project.llil_body(function)?.is_some());
    assert!(project.llil_ssa_body(function)?.is_some());
    let pcode = project
        .ir_artefact(function, IrLevel::PCode)?
        .expect("PCode artefact should be present");
    let llil = project
        .ir_artefact(function, IrLevel::Llil)?
        .expect("LLIL artefact should be present");
    let ssa = project
        .ir_artefact(function, IrLevel::LlilSsa)?
        .expect("LLIL SSA artefact should be present");
    assert_eq!(
        llil.header().parent_digest(),
        pcode.header().content_digest()
    );
    assert_eq!(ssa.header().parent_digest(), llil.header().content_digest());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactPublished {
                function,
                level: IrLevel::Llil,
            })
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactPublished {
                function,
                level: IrLevel::LlilSsa,
            })
    );

    Ok(())
}

#[test]
fn test_ensure_ir_rebuilds_deterministic_content() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;
    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        assert!(transaction.ensure_llil_ssa(function, &BuildStatus::new())?);
        transaction.commit()?;
    }

    let first_pcode = project
        .ir_artefact(function, IrLevel::PCode)?
        .expect("PCode artefact should be present")
        .header()
        .content_digest();
    let first_llil = project
        .ir_artefact(function, IrLevel::Llil)?
        .expect("LLIL artefact should be present")
        .header()
        .content_digest();
    let first_ssa = project
        .ir_artefact(function, IrLevel::LlilSsa)?
        .expect("LLIL SSA artefact should be present")
        .header()
        .content_digest();

    {
        let mut transaction = project.transaction("test");
        assert_eq!(
            transaction.remove_ir_artefacts_from(function, IrLevel::PCode)?,
            3
        );
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        assert!(transaction.ensure_llil_ssa(function, &BuildStatus::new())?);
        transaction.commit()?;
    }

    assert_eq!(
        project
            .ir_artefact(function, IrLevel::PCode)?
            .expect("rebuilt PCode artefact should be present")
            .header()
            .content_digest(),
        first_pcode
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::Llil)?
            .expect("rebuilt LLIL artefact should be present")
            .header()
            .content_digest(),
        first_llil
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::LlilSsa)?
            .expect("rebuilt LLIL SSA artefact should be present")
            .header()
            .content_digest(),
        first_ssa
    );

    Ok(())
}

#[test]
fn test_ensure_ir_reports_missing_parent_artefact() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();

    let mut transaction = project.transaction("test");
    assert!(matches!(
        transaction.ensure_llil(function, &BuildStatus::new()),
        Err(ProjectError::Il(IlError::MissingArtefact {
            level: IrLevel::PCode,
            ..
        }))
    ));
    transaction.rollback()?;

    Ok(())
}

#[test]
fn test_ensure_ir_cancelled_publishes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let revision = project.semantic_revision();

    for level in [IrLevel::PCode, IrLevel::Llil, IrLevel::LlilSsa] {
        let mut transaction = project.transaction("test");
        assert!(matches!(
            transaction.ensure_ir(function, level, &BuildStatus::cancelled()),
            Err(ProjectError::Il(IlError::Cancelled))
        ));
        transaction.rollback()?;
    }

    assert_eq!(project.semantic_revision(), revision);
    assert!(project.ir_artefact(function, IrLevel::PCode)?.is_none());
    assert!(project.ir_artefact(function, IrLevel::Llil)?.is_none());
    assert!(project.ir_artefact(function, IrLevel::LlilSsa)?.is_none());

    Ok(())
}

#[test]
fn test_ensure_ir_reports_unsupported_mlil_levels() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();

    for level in [IrLevel::MappedMlil, IrLevel::Mlil] {
        let mut transaction = project.transaction("test");
        assert!(matches!(
            transaction.ensure_ir(function, level, &BuildStatus::new()),
            Err(ProjectError::Il(IlError::MlilBuildSchedulingUnsupported))
        ));
        transaction.rollback()?;

        assert!(project.ir_artefact(function, level)?.is_none());
    }

    Ok(())
}

#[test]
fn test_publish_ir_rejects_unsupported_mlil_levels() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();

    for level in [IrLevel::MappedMlil, IrLevel::Mlil] {
        let mut transaction = project.transaction("test");
        assert!(matches!(
            transaction.publish_ir_artefact(test_ir_artefact(function, level, Vec::new())),
            Err(ProjectError::Il(IlError::ArtefactLevelUnsupported { level: found }))
                if found == level
        ));
        transaction.rollback()?;

        assert!(project.ir_artefact(function, level)?.is_none());
    }

    Ok(())
}

#[test]
fn test_publish_ir_rejects_missing_parent_digest() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let mut pcode = test_pcode_body(function);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_body(&mut pcode)?;
        transaction.commit()?;
    }

    let header = ArtefactHeader::new(function, IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
    let mut llil = LlilBuilder::new(header, CommonBody::default()).finish(&BuildStatus::new())?;

    let mut transaction = project.transaction("test");
    assert!(matches!(
        transaction.publish_ir_body(&mut llil),
        Err(ProjectError::Il(IlError::MissingParentDigest {
            level: IrLevel::Llil
        }))
    ));
    transaction.rollback()?;

    Ok(())
}

#[test]
fn test_publish_ir_rejects_parent_digest_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let function = FunctionId::default();
    let mut pcode = test_pcode_body(function);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_body(&mut pcode)?;
        transaction.commit()?;
    }

    let mut header = ArtefactHeader::new(function, IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
    header.set_parent_digest(ArtefactDigest::new([1; 32]));
    let mut llil = LlilBuilder::new(header, CommonBody::default()).finish(&BuildStatus::new())?;

    let mut transaction = project.transaction("test");
    assert!(matches!(
        transaction.publish_ir_body(&mut llil),
        Err(ProjectError::Il(IlError::ParentDigestMismatch {
            level: IrLevel::Llil
        }))
    ));
    transaction.rollback()?;

    Ok(())
}

#[test]
fn test_ir_artefact_descendant_removal_preserves_parent() -> Result<(), Box<dyn std::error::Error>>
{
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;

    {
        let mut transaction = project.transaction("test");
        let pcode = test_ir_artefact(FunctionId::default(), IrLevel::PCode, vec![1]);
        let mut llil = test_ir_artefact(FunctionId::default(), IrLevel::Llil, vec![2]);
        llil.set_parent_digest(pcode.header().content_digest());
        let mut ssa = test_ir_artefact(FunctionId::default(), IrLevel::LlilSsa, vec![3]);
        ssa.set_parent_digest(llil.header().content_digest());

        transaction.publish_ir_artefact(pcode)?;
        transaction.publish_ir_artefact(llil)?;
        transaction.publish_ir_artefact(ssa)?;
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        assert_eq!(
            transaction.remove_ir_artefacts_from(FunctionId::default(), IrLevel::Llil)?,
            2
        );
        transaction.rollback()?;
    }

    assert!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::Llil)?
            .is_some()
    );
    assert!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::LlilSsa)?
            .is_some()
    );

    let changes = {
        let mut transaction = project.transaction("test");
        assert_eq!(
            transaction.remove_ir_artefacts_from(FunctionId::default(), IrLevel::Llil)?,
            2
        );
        transaction.commit()?
    };

    assert!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::PCode)?
            .is_some()
    );
    assert!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::Llil)?
            .is_none()
    );
    assert!(
        project
            .ir_artefact(FunctionId::default(), IrLevel::LlilSsa)?
            .is_none()
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function: FunctionId::default(),
                level: IrLevel::Llil,
            })
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function: FunctionId::default(),
                level: IrLevel::LlilSsa,
            })
    );

    Ok(())
}

#[test]
fn test_replacing_function_invalidates_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        let pcode = test_ir_artefact(function, IrLevel::PCode, vec![1]);
        let mut llil = test_ir_artefact(function, IrLevel::Llil, vec![2]);
        llil.set_parent_digest(pcode.header().content_digest());

        transaction.publish_ir_artefact(pcode)?;
        transaction.publish_ir_artefact(llil)?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        assert_eq!(
            transaction.add_function(partial_function(entry, 2))?,
            function
        );
        transaction.commit()?
    };

    assert!(project.ir_artefact(function, IrLevel::PCode)?.is_none());
    assert!(project.ir_artefact(function, IrLevel::Llil)?.is_none());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function,
                level: IrLevel::PCode,
            })
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function,
                level: IrLevel::Llil,
            })
    );

    Ok(())
}

#[test]
fn test_function_replacement_rollback_restores_ir() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let artefact = test_ir_artefact(function, IrLevel::PCode, vec![1]);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(artefact.clone())?;
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        transaction.add_function(partial_function(entry, 2))?;
        transaction.rollback()?;
    }

    assert_eq!(
        project
            .ir_artefact(function, IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(artefact.content_digest())
    );

    let block = project
        .functions()
        .get_by_id(function)
        .and_then(|function| function.blocks().next().map(|(_, block)| block))
        .and_then(|block| project.blocks().get_by_id(block))
        .expect("function body should be restored");
    assert_eq!(block.len(), 1);

    Ok(())
}

#[test]
fn test_removing_function_invalidates_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(test_ir_artefact(function, IrLevel::PCode, vec![1]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_function_by_id(function)?);
        transaction.commit()?
    };

    assert!(project.ir_artefact(function, IrLevel::PCode)?.is_none());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function,
                level: IrLevel::PCode,
            })
    );

    Ok(())
}

#[test]
fn test_byte_write_invalidates_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 2))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(test_ir_artefact(function, IrLevel::PCode, vec![1]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry + 1u64, &[0xa5])?;
        transaction.commit()?
    };

    assert!(project.ir_artefact(function, IrLevel::PCode)?.is_none());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function,
                level: IrLevel::PCode,
            })
    );

    Ok(())
}

#[test]
fn test_byte_write_invalidates_ir_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 2))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        let pcode = test_ir_artefact(function, IrLevel::PCode, vec![1]);
        let mut llil = test_ir_artefact(function, IrLevel::Llil, vec![2]);
        llil.set_parent_digest(pcode.header().content_digest());
        let mut ssa = test_ir_artefact(function, IrLevel::LlilSsa, vec![3]);
        ssa.set_parent_digest(llil.header().content_digest());

        transaction.publish_ir_artefact(pcode)?;
        transaction.publish_ir_artefact(llil)?;
        transaction.publish_ir_artefact(ssa)?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry + 1u64, &[0xa5])?;
        transaction.commit()?
    };

    for level in [IrLevel::PCode, IrLevel::Llil, IrLevel::LlilSsa] {
        assert!(project.ir_artefact(function, level)?.is_none());
        assert!(
            changes
                .records()
                .contains(&ChangeRecord::IrArtefactRemoved { function, level })
        );
    }

    Ok(())
}

#[test]
fn test_symbol_rename_preserves_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 250);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 2))?;
        transaction.insert_symbol(
            index,
            SymbolEntry::new(entry, "old_display_name", SymbolProperties::FUNCTION),
        );
        transaction.commit()?;
        function
    };

    let pcode = test_ir_artefact(function, IrLevel::PCode, vec![1]);
    let mut llil = test_ir_artefact(function, IrLevel::Llil, vec![2]);
    llil.set_parent_digest(pcode.header().content_digest());
    let mut ssa = test_ir_artefact(function, IrLevel::LlilSsa, vec![3]);
    ssa.set_parent_digest(llil.header().content_digest());

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(pcode.clone())?;
        transaction.publish_ir_artefact(llil.clone())?;
        transaction.publish_ir_artefact(ssa.clone())?;
        transaction.commit()?;
    }

    let semantic_revision = project.semantic_revision();
    let changes = {
        let mut transaction = project.transaction("test");
        transaction.insert_symbol(
            index,
            SymbolEntry::new(entry, "new_display_name", SymbolProperties::FUNCTION),
        );
        transaction.commit()?
    };

    assert_eq!(project.semantic_revision(), semantic_revision);
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::IrArtefactRemoved { .. }))
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(pcode.content_digest())
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::Llil)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(llil.content_digest())
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::LlilSsa)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(ssa.content_digest())
    );

    Ok(())
}

#[test]
fn test_reference_edits_preserve_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;
    let target = entry + 0x10u64;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 2))?;
        transaction.commit()?;
        function
    };

    let pcode = test_ir_artefact(function, IrLevel::PCode, vec![1]);
    let mut llil = test_ir_artefact(function, IrLevel::Llil, vec![2]);
    llil.set_parent_digest(pcode.header().content_digest());
    let mut ssa = test_ir_artefact(function, IrLevel::LlilSsa, vec![3]);
    ssa.set_parent_digest(llil.header().content_digest());

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(pcode.clone())?;
        transaction.publish_ir_artefact(llil.clone())?;
        transaction.publish_ir_artefact(ssa.clone())?;
        transaction.commit()?;
    }

    let semantic_revision = project.semantic_revision();
    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.add_reference(Reference::new(entry, target, ReferenceKind::read()))?);
        transaction.commit()?
    };

    assert_eq!(project.semantic_revision(), semantic_revision);
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::IrArtefactRemoved { .. }))
    );

    let changes = {
        let mut transaction = project.transaction("test");
        assert!(transaction.remove_reference(entry, ReferenceTarget::from(target))?);
        transaction.commit()?
    };

    assert_eq!(project.semantic_revision(), semantic_revision);
    assert!(
        !changes
            .records()
            .iter()
            .any(|record| matches!(record, ChangeRecord::IrArtefactRemoved { .. }))
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(pcode.content_digest())
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::Llil)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(llil.content_digest())
    );
    assert_eq!(
        project
            .ir_artefact(function, IrLevel::LlilSsa)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(ssa.content_digest())
    );

    Ok(())
}

#[test]
fn test_byte_write_rollback_restores_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = writable_address(&project)?;

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let artefact = test_ir_artefact(function, IrLevel::PCode, vec![1]);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(artefact.clone())?;
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        transaction.write_bytes(entry, &[0xa5])?;
        transaction.rollback()?;
    }

    assert_eq!(
        project
            .ir_artefact(function, IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(artefact.content_digest())
    );

    Ok(())
}

#[test]
fn test_mapping_removal_invalidates_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping, range) = first_mapping_placement(&project);
    let entry = Address::new(space, range.0);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(test_ir_artefact(function, IrLevel::PCode, vec![1]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.remove_mapping(mapping)?;
        transaction.commit()?
    };

    assert!(project.ir_artefact(function, IrLevel::PCode)?.is_none());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function,
                level: IrLevel::PCode,
            })
    );

    Ok(())
}

#[test]
fn test_mapping_removal_rollback_restores_ir_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping, range) = first_mapping_placement(&project);
    let entry = Address::new(space, range.0);

    let function = {
        let mut transaction = project.transaction("test");
        let function = transaction.add_function(partial_function(entry, 1))?;
        transaction.commit()?;
        function
    };
    let artefact = test_ir_artefact(function, IrLevel::PCode, vec![1]);

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(artefact.clone())?;
        transaction.commit()?;
    }

    {
        let mut transaction = project.transaction("test");
        transaction.remove_mapping(mapping)?;
        transaction.rollback()?;
    }

    assert_eq!(
        project
            .ir_artefact(function, IrLevel::PCode)?
            .as_ref()
            .map(RawIrArtefact::content_digest),
        Some(artefact.content_digest())
    );

    Ok(())
}

#[test]
fn test_mapping_remap_invalidates_old_and_new_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping, old_range) = first_mapping_placement(&project);
    let old_entry = Address::new(space, old_range.0);
    let new_start = project
        .segments()
        .mapping(mapping)
        .expect("mapping should exist")
        .start()
        + 0x1000000u64;
    let new_entry = Address::new(space, new_start.raw_address());

    let (old_function, new_function) = {
        let mut transaction = project.transaction("test");
        let old_function = transaction.add_function(partial_function(old_entry, 1))?;
        let new_function = transaction.add_function(partial_function(new_entry, 1))?;
        transaction.commit()?;
        (old_function, new_function)
    };

    {
        let mut transaction = project.transaction("test");
        transaction.publish_ir_artefact(test_ir_artefact(old_function, IrLevel::PCode, vec![1]))?;
        transaction.publish_ir_artefact(test_ir_artefact(new_function, IrLevel::PCode, vec![2]))?;
        transaction.commit()?;
    }

    let changes = {
        let mut transaction = project.transaction("test");
        transaction.remap_mapping(mapping, new_start)?;
        transaction.commit()?
    };

    assert!(project.ir_artefact(old_function, IrLevel::PCode)?.is_none());
    assert!(project.ir_artefact(new_function, IrLevel::PCode)?.is_none());
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function: old_function,
                level: IrLevel::PCode,
            })
    );
    assert!(
        changes
            .records()
            .contains(&ChangeRecord::IrArtefactRemoved {
                function: new_function,
                level: IrLevel::PCode,
            })
    );

    Ok(())
}

#[test]
fn test_removing_mapping_records_unmapped_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");

    let mut transaction = project.transaction("test");
    transaction.remove_mapping(mapping)?;
    let changes = transaction.commit()?;

    assert!(changes.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping,
        range: AddressRange::new(space, range.0, range.1),
    }));

    Ok(())
}

#[test]
fn test_remapping_mapping_records_old_and_new_ranges() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let old_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");
    let new_start = project
        .segments()
        .mapping(mapping)
        .expect("mapping should exist")
        .start()
        + 0x1000000u64;

    let mut transaction = project.transaction("test");
    transaction.remap_mapping(mapping, new_start)?;
    let changes = transaction.commit()?;

    let new_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should keep its placement after remap");

    assert!(changes.records().contains(&ChangeRecord::SegmentUnmapped {
        mapping,
        range: AddressRange::new(space, old_range.0, old_range.1),
    }));
    assert!(changes.records().contains(&ChangeRecord::SegmentMapped {
        mapping,
        range: AddressRange::new(space, new_range.0, new_range.1),
    }));

    Ok(())
}

#[test]
fn test_removing_mapping_rollback_restores_placement() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let old_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");

    let mut transaction = project.transaction("test");
    transaction.remove_mapping(mapping)?;
    transaction.rollback()?;

    assert_eq!(
        project
            .segments()
            .mapping_placements(mapping)
            .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range)),
        Some(old_range)
    );

    Ok(())
}

#[test]
fn test_remapping_mapping_rollback_restores_old_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let (space, mapping) = project
        .segments()
        .spaces()
        .find_map(|space| {
            space
                .priority_list()
                .first()
                .map(|mapping_ref| (space.id(), mapping_ref.mapping_id()))
        })
        .expect("fixture should contain at least one mapping");
    let old_range = project
        .segments()
        .mapping_placements(mapping)
        .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range))
        .expect("mapping should have a placement in its priority space");
    let new_start = project
        .segments()
        .mapping(mapping)
        .expect("mapping should exist")
        .start()
        + 0x1000000u64;

    let mut transaction = project.transaction("test");
    transaction.remap_mapping(mapping, new_start)?;
    transaction.rollback()?;

    assert_eq!(
        project
            .segments()
            .mapping_placements(mapping)
            .find_map(|(mapped_space, range)| (mapped_space == space).then_some(range)),
        Some(old_range)
    );

    Ok(())
}

#[test]
fn test_create_space_rollback_removes_space() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;

    let mut transaction = project.transaction("test");
    let space = transaction.create_space()?;
    transaction.rollback()?;

    assert!(!project.segments().spaces().any(|s| s.id() == space));

    let mut transaction = project.transaction("test");
    let recreated = transaction.create_space()?;
    transaction.commit()?;

    assert_eq!(recreated, space);

    Ok(())
}

#[test]
fn test_write_bytes_rollback_restores_old_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let address = writable_address(&project)?;
    let mut old = [0u8; 1];
    project.segments().read_bytes_exact(address, &mut old)?;
    let patch = [old[0] ^ 0xff];

    let mut transaction = project.transaction("test");
    transaction.write_bytes(address, &patch)?;
    let mut patched = [0u8; 1];
    transaction
        .project()
        .segments()
        .read_bytes_exact(address, &mut patched)?;
    assert_eq!(patched, patch);
    transaction.rollback()?;

    let mut restored = [0u8; 1];
    project
        .segments()
        .read_bytes_exact(address, &mut restored)?;
    assert_eq!(restored, old);

    Ok(())
}

#[test]
fn test_partial_write_bytes_restores_before_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let address = project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .filter(|view| view.properties().is_writable())
        .max_by_key(|view| view.last())
        .map(|view| view.last())
        .ok_or_else(|| io::Error::other("fixture writable segment missing"))?;
    let mut old = [0u8; 1];
    project.segments().read_bytes_exact(address, &mut old)?;

    let mut transaction = project.transaction("test");
    assert!(
        transaction
            .write_bytes(address, &[old[0] ^ 0xff, 0xdd])
            .is_err()
    );
    let mut restored = [0u8; 1];
    transaction
        .project()
        .segments()
        .read_bytes_exact(address, &mut restored)?;
    assert_eq!(restored, old);
    transaction.rollback()?;

    Ok(())
}

#[test]
fn test_replacing_function_removes_old_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = PartialFunction::new(entry);
    first.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(first)?;
    let changes = transaction.commit()?;

    let mut covered = AddressRangeSet::new();
    covered.insert(entry);
    assert_eq!(
        changes.records(),
        &[ChangeRecord::FunctionAdded {
            entry,
            coverage: covered,
        }]
    );
    assert_eq!(project.blocks().len(), 1);

    let old_block = project
        .functions()
        .get_by_address(entry)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");

    let mut second = PartialFunction::new(entry);
    second.push_block(PartialCodeBlock::new(
        entry,
        2,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(second)?;
    let changes = transaction.commit()?;

    let mut covered = AddressRangeSet::new();
    covered.insert_raw_range(
        entry.space(),
        entry.raw_address()..=(entry + 1u64).raw_address(),
    );
    assert_eq!(
        changes.records(),
        &[ChangeRecord::FunctionChanged {
            entry,
            kind: FunctionChangeKind::Body,
            coverage: covered,
        }]
    );
    assert!(project.blocks().get_by_id(old_block).is_none());
    assert_eq!(project.blocks().len(), 1);

    Ok(())
}

#[test]
fn test_function_rollback_restores_previous_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = PartialFunction::new(entry);
    first.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(first)?;
    transaction.commit()?;

    let old_block = project
        .functions()
        .get_by_address(entry)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");

    let mut second = PartialFunction::new(entry);
    second.push_block(PartialCodeBlock::new(
        entry,
        2,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(second)?;
    transaction.rollback()?;

    let function = project
        .functions()
        .get_by_address(entry)
        .expect("function should be restored");
    let blocks = function.blocks().collect::<Vec<_>>();
    assert_eq!(blocks, vec![(entry, old_block)]);
    assert!(project.blocks().get_by_id(old_block).is_some());
    assert_eq!(project.blocks().len(), 1);

    Ok(())
}

#[test]
fn test_function_rollback_removes_new_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut function = PartialFunction::new(entry);
    function.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    transaction.add_function(function)?;
    transaction.rollback()?;

    assert!(project.functions().get_by_address(entry).is_none());
    assert_eq!(project.blocks().len(), 0);

    Ok(())
}

#[test]
fn test_function_rollback_restores_allocated_ids() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let entry = Address::from(0x4000u64);

    let mut first = PartialFunction::new(entry);
    first.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    let rolled_back_function = transaction.add_function(first)?;
    let rolled_back_block = transaction
        .project()
        .functions()
        .get_by_id(rolled_back_function)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");
    transaction.rollback()?;

    let mut second = PartialFunction::new(entry);
    second.push_block(PartialCodeBlock::new(
        entry,
        1,
        Vec::new(),
        ContextSet::default(),
    ));

    let mut transaction = project.transaction("test");
    let committed_function = transaction.add_function(second)?;
    transaction.commit()?;
    let committed_block = project
        .functions()
        .get_by_id(committed_function)
        .and_then(|function| function.blocks().next().map(|(_, id)| id))
        .expect("function should have one block");

    assert_eq!(committed_function, rolled_back_function);
    assert_eq!(committed_block, rolled_back_block);

    Ok(())
}

#[test]
fn test_symbol_rollback_removes_new_symbol() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let selector = SymbolTableSelector::new(253);
    let index = SymbolIndex::new(selector, 0);
    let entry = Address::from(0x4010u64);
    let symbol = SymbolEntry::new(entry, "rollback_new_symbol", SymbolProperties::FUNCTION);

    let mut transaction = project.transaction("test");
    let rolled_back_id = transaction.insert_symbol(index, symbol.clone());
    transaction.rollback()?;

    assert!(project.symbols().get_by_index(index).is_none());
    assert!(project.symbols().get_by_address(entry).next().is_none());

    let mut transaction = project.transaction("test");
    let committed_id = transaction.insert_symbol(index, symbol);
    transaction.commit()?;

    assert_eq!(committed_id, rolled_back_id);

    Ok(())
}

#[test]
fn test_symbol_rollback_restores_replaced_index() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 1);
    let old_entry = Address::from(0x4020u64);
    let new_entry = Address::from(0x4030u64);

    let mut transaction = project.transaction("test");
    let old_id = transaction.insert_symbol(
        index,
        SymbolEntry::new(old_entry, "rollback_old_symbol", SymbolProperties::FUNCTION),
    );
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    transaction.insert_symbol(
        index,
        SymbolEntry::new(new_entry, "rollback_new_symbol", SymbolProperties::DATA),
    );
    transaction.rollback()?;

    let (restored_id, restored) = project
        .symbols()
        .get_by_index(index)
        .expect("symbol index should be restored");
    assert_eq!(restored_id, old_id);
    assert_eq!(restored.address(), old_entry);
    assert_eq!(restored.symbol().as_str(), "rollback_old_symbol");
    assert!(project.symbols().get_by_address(new_entry).next().is_none());

    Ok(())
}

#[test]
fn test_symbol_rollback_restores_removed_symbol() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient(Fixtures::binary("ls.elf"))?;
    let index = SymbolIndex::new(SymbolTableSelector::new(253), 2);
    let entry = Address::from(0x4040u64);

    let mut transaction = project.transaction("test");
    let id = transaction.insert_symbol(
        index,
        SymbolEntry::new(entry, "rollback_removed_symbol", SymbolProperties::FUNCTION),
    );
    transaction.commit()?;

    let mut transaction = project.transaction("test");
    assert!(transaction.remove_symbol_by_index(index));
    transaction.rollback()?;

    let (restored_id, restored) = project
        .symbols()
        .get_by_index(index)
        .expect("symbol index should be restored");
    assert_eq!(restored_id, id);
    assert_eq!(restored.address(), entry);
    assert_eq!(restored.symbol().as_str(), "rollback_removed_symbol");

    Ok(())
}
