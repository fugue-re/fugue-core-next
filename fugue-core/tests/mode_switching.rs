use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::{fs, iter};

use fallible_iterator::{FallibleIterator, convert};
use fugue_core::analysis::function::{
    FunctionCandidate, FunctionRecovery, FunctionRecoveryConfig, FunctionRecoveryExtension,
    LinearSweepConfig, StructuredFunctionContext,
};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::{Arch, Arm, Mips, Mips64, X86_64};
use fugue_core::engine::{AnalysisContext, AnalysisEngine, AnalysisEngineConfig};
use fugue_core::extension;
use fugue_core::ir::{Address, AddressWithContext, Endian, RawAddress};
use fugue_core::lifter::{ContextBitRange, ContextHint, ContextSet, Language, RawPCodeOp, Varnode};
use fugue_core::loader::{
    ImageAddress, ImageBacking, ImageLayout, ImageSegment, ImageSegmentContents,
    ImageSegmentContentsIterator, ImageSegmentIterator, Loadable, LoadableMetadata, Loader,
    LoaderError,
};
use fugue_core::project::Project;
use fugue_core::storage::{
    AddressSpaceId, SegmentMappingHints, SegmentMappingProvenance, SegmentProperties,
};
use fugue_core::types::{AttributeMap, Confidence};
use object::{Object, ObjectSection, ObjectSymbol};

const CANDIDATES_ATTRIBUTE: &str = "fugue.test.candidates";
const MODE_CANDIDATES_ATTRIBUTE: &str = "fugue.test.mode-candidates";

#[derive(Clone, Copy)]
struct SegmentSpec {
    address: u64,
    backing: u64,
    size: u64,
}

struct ModeImage {
    arch: Arch,
    attributes: AttributeMap,
    bytes: Vec<u8>,
    entry_point: Option<u64>,
    layout: ImageLayout,
    mapping_hints: Vec<(u64, ContextHint)>,
    metadata: LoadableMetadata,
    segments: Vec<SegmentSpec>,
}

impl Loadable for ModeImage {
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

    fn entry_point(&self) -> Option<ImageAddress> {
        self.entry_point.map(ImageAddress::in_default_space)
    }

    fn image_layout(&self) -> &ImageLayout {
        &self.layout
    }

    fn image_segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
        Box::new(convert(self.segments.iter().enumerate().map(
            |(index, segment)| {
                let translate = |offset: u64| {
                    (segment.backing..segment.backing + segment.size)
                        .contains(&offset)
                        .then(|| RawAddress::from(segment.address + offset - segment.backing))
                };
                let last = RawAddress::from(segment.address + segment.size - 1);
                let mut mapping_hints = SegmentMappingHints::default();
                for (address, hint) in &self.mapping_hints {
                    if let Some(address) = translate(*address) {
                        mapping_hints.insert_context_hint_range(address..=last, hint.clone());
                    }
                }
                Ok(ImageSegment::new(
                    format!("mode-{index}"),
                    ImageAddress::in_default_space(segment.address),
                    segment.size,
                    SegmentProperties::PERM_ALL,
                )
                .with_backing(ImageBacking::in_default_bank(segment.backing))
                .with_mapping_hints(mapping_hints)
                .with_provenance(SegmentMappingProvenance::Segment))
            },
        ))) as ImageSegmentIterator<'a>
    }

    fn image_contents<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a {
        let contents = ImageSegmentContents::new(
            0u64,
            self.arch.endian(),
            Cow::Borrowed(self.bytes.as_slice()),
        );
        Box::new(convert(iter::once(Ok(contents)))) as ImageSegmentContentsIterator<'a>
    }
}

impl ModeImage {
    fn new(
        language: &'static Language,
        bytes: Vec<u8>,
        segments: Vec<SegmentSpec>,
    ) -> Result<Self, LoaderError> {
        Ok(Self {
            arch: Arch::new(language),
            attributes: AttributeMap::new(),
            entry_point: None,
            layout: ImageLayout::single_bank(bytes.len() as u64)?,
            mapping_hints: Vec::new(),
            metadata: LoadableMetadata::new(&bytes, "MIPS mode switching"),
            bytes,
            segments,
        })
    }
}

struct CheckBlockFlowContexts;

impl AnalysisPass<StructuredFunctionContext> for CheckBlockFlowContexts {
    fn analyse_with(
        &mut self,
        _context: &mut AnalysisContext<'_, '_>,
        state: &mut StructuredFunctionContext,
    ) -> Result<(), AnalysisError> {
        let function = state.function();
        for block in function.blocks() {
            for target in function.block_flow_targets(block) {
                assert_eq!(target.from().context(), block.context());
            }
        }
        Ok(())
    }
}

#[extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "mips-mode-switching-test";

    fn configure(project: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        if let Some(candidates) = project
            .attributes()
            .get_attr::<Vec<u64>>(CANDIDATES_ATTRIBUTE)
        {
            for candidate in candidates {
                recovery.add_candidate(FunctionCandidate::new_with(
                    AddressWithContext::new(
                        Address::in_default_space(candidate),
                        ContextSet::new(),
                    ),
                    Confidence::somewhat_certain(),
                ));
            }
        }
        let Some(candidates) = project
            .attributes()
            .get_attr::<Vec<u64>>(MODE_CANDIDATES_ATTRIBUTE)
        else {
            return Ok(());
        };
        recovery.add_post_structuring_pass("check-block-flow-contexts", CheckBlockFlowContexts);
        for candidate in candidates {
            recovery.add_candidate(FunctionCandidate::new_with(
                AddressWithContext::new(
                    Address::in_default_space(candidate),
                    mips16_context(project.language()),
                ),
                Confidence::somewhat_certain(),
            ));
        }
        Ok(())
    }
}

fn mips16_context(language: &Language) -> ContextSet {
    let isa_mode = language
        .context_variable_by_name("ISA_MODE")
        .expect("MIPS language must define ISA_MODE");
    let pair_flag = language
        .context_variable_by_name("PAIR_INSTRUCTION_FLAG")
        .expect("MIPS language must define PAIR_INSTRUCTION_FLAG");
    let mut context = ContextSet::single(isa_mode, 1);
    context.merge(&ContextSet::single(pair_flag, 0));
    context
}

fn mips_variants() -> Result<Vec<&'static Language>, Box<dyn Error>> {
    Ok(vec![
        Mips::resolve_default_variant(Endian::Big)?,
        Mips::resolve_default_variant(Endian::Little)?,
        Mips64::resolve_default_variant(Endian::Big)?,
        Mips64::resolve_default_variant(Endian::Little)?,
        Mips64::resolve_variant(Endian::Big, "64-32addr")?,
        Mips64::resolve_variant(Endian::Little, "64-32addr")?,
    ])
}

fn link_value(operations: &[RawPCodeOp], link_register: Varnode) -> u64 {
    operations
        .iter()
        .find(|operation| operation.output() == Some(&link_register))
        .expect("lifted call must assign the link register")
        .inputs()
        .iter()
        .fold(0u64, |value, input| value | input.offset())
}

#[test]
fn archived_context_preserves_word_positions_values_and_update_order() -> Result<(), Box<dyn Error>>
{
    let address = Address::new(AddressSpaceId::new(7), RawAddress::from(u64::MAX));
    let word = ContextBitRange::new(224, 255);
    let bit = ContextBitRange::new(255, 255);
    let context = ContextSet::from_iter([(word, u32::MAX), (bit, 0)]);
    let candidate = AddressWithContext::new(address, context);
    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&candidate)?;
    let decoded = rkyv::from_bytes::<AddressWithContext, rkyv::rancor::Error>(&encoded)?;
    assert_eq!(decoded, candidate);
    for candidate in [
        AddressWithContext::from(address),
        AddressWithContext::new(address, ContextSet::single(bit, 0)),
        AddressWithContext::new(address, ContextSet::single(word, u32::MAX)),
    ] {
        let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&candidate)?;
        let decoded = rkyv::from_bytes::<AddressWithContext, rkyv::rancor::Error>(&encoded)?;
        assert_eq!(decoded, candidate);
    }
    assert_ne!(ContextSet::single(bit, 0), ContextSet::new());
    assert!(ContextSet::single(bit, 255) < ContextSet::single(bit, 256));

    let language = Mips::resolve_default_variant(Endian::Big)?;
    let mut lifter = Arch::new(language).lifter();
    lifter
        .context_mut()
        .register_variable("last_word", 224, 255);
    decoded.context().apply(address, lifter.context_mut());
    assert_eq!(
        lifter
            .context()
            .get_variable_by_bits(word, address.offset()),
        u32::MAX - 1
    );

    let mut merged = ContextSet::new();
    merged.merge(decoded.context());
    merged.merge(&ContextSet::single(bit, 1));
    merged.apply(address, lifter.context_mut());
    assert_eq!(
        lifter
            .context()
            .get_variable_by_bits(word, address.offset()),
        u32::MAX
    );
    Ok(())
}

#[test]
fn archived_context_rejects_invalid_tags_and_offsets() -> Result<(), Box<dyn Error>> {
    let address = Address::in_default_space(0x1000u64);
    let context = ContextSet::from_iter([
        (ContextBitRange::new(0, 0), 1),
        (ContextBitRange::new(32, 32), 0),
    ]);
    let candidate = AddressWithContext::new(address, context);
    let encoded = rkyv::to_bytes::<rkyv::rancor::Error>(&candidate)?;
    let root = encoded.len() - size_of::<rkyv::Archived<AddressWithContext>>();

    let mut invalid_tag = encoded.clone();
    *invalid_tag.last_mut().expect("archive contains an address") = 254;
    assert!(rkyv::from_bytes::<AddressWithContext, rkyv::rancor::Error>(&invalid_tag).is_err());

    let mut invalid_offset = encoded;
    invalid_offset[root + 8..root + 12].fill(0x7f);
    assert!(rkyv::from_bytes::<AddressWithContext, rkyv::rancor::Error>(&invalid_offset).is_err());
    Ok(())
}

#[test]
fn mips_canonicalisation_tracks_isa_mode_for_every_variant() -> Result<(), Box<dyn Error>> {
    for language in mips_variants()? {
        let arch = Arch::new(language);
        let isa_mode = language
            .context_variable_by_name("ISA_MODE")
            .expect("MIPS language must define ISA_MODE");

        let (canonical, context) = arch
            .canonicalise_address(0x1001u64)
            .expect("an odd MIPS address selects MIPS16 mode");
        assert_eq!(canonical, RawAddress::from(0x1000u64));
        assert_eq!(context, ContextSet::single(isa_mode, 1));

        assert!(arch.canonicalise_address(0x1002u64).is_none());

        let mut lifter = arch.lifter();
        lifter
            .context_mut()
            .set_variable_by_bits(isa_mode, 0x1002, 1);
        let (canonical, context) = arch
            .canonicalise_address_with(0x1002u64, lifter.context())
            .expect("an even halfword address is valid in MIPS16 mode");
        assert_eq!(canonical, RawAddress::from(0x1002u64));
        assert_eq!(context, ContextSet::single(isa_mode, 1));
    }

    Ok(())
}

#[test]
fn generic_disassembler_uses_the_supplied_mips_context() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let arch = Arch::new(language);
    let isa_mode = language
        .context_variable_by_name("ISA_MODE")
        .expect("MIPS language must define ISA_MODE");
    let address = Address::in_default_space(0x1000u64);
    let mut lifter = arch.lifter();
    let mut disassembler = arch.disassembler();

    lifter
        .context_mut()
        .set_variable_by_bits(isa_mode, address.offset(), 1);
    let instruction = disassembler.disassemble(address, [0x68, 0x01], lifter.context_mut())?;

    assert_eq!(instruction.size(), 2);
    Ok(())
}

#[test]
fn mips_jalx_uses_the_address_after_its_delay_slot() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let arch = Arch::new(language);
    let isa_mode = language
        .context_variable_by_name("ISA_MODE")
        .expect("MIPS language must define ISA_MODE");
    let link_register = language
        .register_by_name("ra")
        .expect("MIPS language must define ra");
    let address = Address::in_default_space(0x1000u64);

    let mut mips16 = arch.lifter();
    mips16
        .context_mut()
        .set_variable_by_bits(isa_mode, address.offset(), 1);
    let mut operations = Vec::new();
    let size = mips16.lift(
        address,
        &[0x1c, 0x00, 0x08, 0x00, 0x65, 0x00],
        &mut operations,
    )?;
    assert_eq!(size, 6);
    assert_eq!(link_value(&operations, link_register), 0x1007);
    assert_eq!(mips16.context().get_variable_by_bits(isa_mode, 0x2000), 0);

    let mut mips32 = arch.lifter();
    operations.clear();
    let size = mips32.lift(
        address,
        &[0x74, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00],
        &mut operations,
    )?;
    assert_eq!(size, 8);
    assert_eq!(link_value(&operations, link_register), 0x1008);
    assert_eq!(mips32.context().get_variable_by_bits(isa_mode, 0x2000), 1);

    Ok(())
}

#[test]
fn thumb_blx_commits_arm_mode_at_its_target() -> Result<(), Box<dyn Error>> {
    let language = Arm::resolve_default_variant(Endian::Little)?;
    let arch = Arch::new(language);
    let t_mode = language
        .context_variable_by_name("TMode")
        .expect("ARM language must define TMode");
    let address = Address::in_default_space(0x4c8u64);

    let mut thumb = arch.lifter();
    thumb
        .context_mut()
        .set_variable_default("TMode", 1)
        .expect("TMode is a context variable");
    let mut operations = Vec::new();
    let size = thumb.lift(address, &[0xff, 0xf7, 0x3a, 0xef], &mut operations)?;
    assert_eq!(size, 4);
    assert_eq!(thumb.context().get_variable_by_bits(t_mode, 0x340), 0);

    Ok(())
}

#[test]
fn odd_addresses_are_not_mode_tags_on_x86() -> Result<(), Box<dyn Error>> {
    let arch = Arch::new(X86_64::resolve_default_variant()?);
    let (canonical, context) = arch
        .canonicalise_address(0x1001u64)
        .expect("an odd x86 address is valid");

    assert_eq!(canonical, RawAddress::from(0x1001u64));
    assert!(context.is_empty());
    Ok(())
}

fn assert_mode_switching_function(project: &Project, entry: Address) {
    let function = project
        .functions()
        .get_by_address(entry)
        .expect("MIPS16 function must be recovered");
    let blocks = function
        .blocks()
        .map(|(address, block)| {
            let size = project
                .blocks()
                .get_by_id(block)
                .expect("function block must exist")
                .size();
            (address, size)
        })
        .collect::<Vec<_>>();

    assert_eq!(blocks, [(entry, 6), (entry + 6usize, 2)]);
}

#[test]
fn recovery_preserves_explicit_mode_across_a_jalx_fallthrough() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let mut image = ModeImage::new(
        language,
        vec![0x1c, 0x00, 0x08, 0x00, 0x65, 0x00, 0x68, 0x01],
        vec![SegmentSpec {
            address: 0x1000,
            backing: 0,
            size: 8,
        }],
    )?;
    image
        .attributes
        .set_attr(MODE_CANDIDATES_ATTRIBUTE, vec![0x1000u64]);
    image.entry_point = Some(0x1000);

    let engine = AnalysisEngine::new(Project::new_transient(&image)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let entry = Address::in_default_space(0x1000u64);
    assert_mode_switching_function(&project, entry);
    let target = project
        .functions()
        .get_by_address(entry)
        .expect("MIPS16 function must be recovered")
        .flow_targets(project.blocks())
        .find(|target| target.kind().is_call())
        .expect("JALX target must be retained");
    let isa_mode = language
        .context_variable_by_name("ISA_MODE")
        .expect("MIPS language must define ISA_MODE");
    assert_eq!(target.to().address(), Address::in_default_space(0x2000u64));
    assert_eq!(target.from().context(), &mips16_context(language));
    assert_eq!(target.to().context(), &ContextSet::single(isa_mode, 0));
    Ok(())
}

#[test]
fn recovery_applies_mapping_mode_before_entry_canonicalisation() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let isa_mode = language
        .context_variable_by_name("ISA_MODE")
        .expect("MIPS language must define ISA_MODE");
    let mut image = ModeImage::new(
        language,
        vec![0x00, 0x00, 0x1c, 0x00, 0x08, 0x00, 0x65, 0x00, 0x68, 0x01],
        vec![SegmentSpec {
            address: 0x1000,
            backing: 0,
            size: 10,
        }],
    )?;
    image.entry_point = Some(0x1002);
    image.mapping_hints.push((
        0,
        ContextHint::code().with_context(ContextSet::single(isa_mode, 1)),
    ));

    let engine = AnalysisEngine::new(Project::new_transient(&image)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    assert_mode_switching_function(&project, Address::in_default_space(0x1002u64));
    Ok(())
}

#[test]
fn recovery_rejects_tagged_candidates_in_data_regions() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let mut image = ModeImage::new(
        language,
        vec![0x68, 0x01],
        vec![SegmentSpec {
            address: 0x1000,
            backing: 0,
            size: 2,
        }],
    )?;
    image.entry_point = Some(0x1001);
    image.mapping_hints.push((0, ContextHint::data()));

    let engine = AnalysisEngine::new(Project::new_transient(&image)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    assert!(project.functions().is_empty());
    Ok(())
}

#[test]
fn recovery_preserves_supplied_context_across_mapping_boundaries() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let mut image = ModeImage::new(
        language,
        vec![0x68, 0x01, 0x68, 0x02],
        vec![
            SegmentSpec {
                address: 0x1000,
                backing: 0,
                size: 2,
            },
            SegmentSpec {
                address: 0x1002,
                backing: 2,
                size: 2,
            },
        ],
    )?;
    image
        .attributes
        .set_attr(MODE_CANDIDATES_ATTRIBUTE, vec![0x1000u64]);
    image.entry_point = Some(0x1000);

    let engine = AnalysisEngine::new(Project::new_transient(&image)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;
    let entry = Address::in_default_space(0x1000u64);
    let boundary = entry + 2usize;
    let function = project
        .functions()
        .get_by_address(entry)
        .expect("MIPS16 function must be recovered");
    let block = function
        .blocks()
        .find_map(|(address, block)| (address == boundary).then_some(block))
        .and_then(|block| project.blocks().get_by_id(block))
        .expect("the mapping boundary must start a block");

    assert_eq!(block.context(), &mips16_context(language));
    Ok(())
}

#[test]
fn recovery_preserves_candidate_confidence_and_resets_mode() -> Result<(), Box<dyn Error>> {
    let language = Mips::resolve_default_variant(Endian::Big)?;
    let mut image = ModeImage::new(
        language,
        vec![0x68, 0x01, 0x68, 0x02],
        vec![
            SegmentSpec {
                address: 0x1000,
                backing: 0,
                size: 2,
            },
            SegmentSpec {
                address: 0x2000,
                backing: 2,
                size: 2,
            },
        ],
    )?;
    image
        .attributes
        .set_attr(MODE_CANDIDATES_ATTRIBUTE, vec![0x1000u64, 0x2000u64]);
    image.entry_point = Some(0x1000);
    for workers in [1, 2] {
        let config = AnalysisEngineConfig::default().with_worker_limit(workers);
        let engine = AnalysisEngine::with_config(Project::new_transient(&image)?, config)?;
        engine.analyse()?;
        let project = engine.into_project()?;

        for address in [0x1000u64, 0x2000u64] {
            let function = project
                .functions()
                .get_by_address(Address::in_default_space(address))
                .expect("candidate must be recovered in its supplied mode");
            assert_eq!(function.confidence(), Confidence::somewhat_certain());
        }
    }
    Ok(())
}

#[test]
fn thumb_call_flow() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/thumb-calls.elf")?;
    let engine = AnalysisEngine::new(Project::new_transient(&loader)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let t_mode = project
        .arch()
        .language()
        .context_variable_by_name("TMode")
        .expect("ARM language must define TMode");
    let thumb = ContextSet::single(t_mode, 1);

    let mut calls = Vec::new();
    for function in project.functions().iter() {
        calls.extend(
            function
                .flow_targets(project.blocks())
                .filter(|target| target.kind().is_call()),
        );
    }

    assert!(
        calls
            .iter()
            .any(|call| call.to().address() < call.from().address())
    );
    assert!(calls.iter().all(|call| call.to().context() == &thumb));
    assert!(calls.iter().all(|call| {
        project
            .functions()
            .get_by_address(call.to().address())
            .and_then(|function| function.entry_with_context(project.blocks()))
            .is_some_and(|entry| entry.context() == &thumb)
    }));
    Ok(())
}

#[test]
fn thumb_exidx_functions() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/thumb-exidx.elf")?;
    let engine = AnalysisEngine::new(Project::new_transient(&loader)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let t_mode = project
        .arch()
        .language()
        .context_variable_by_name("TMode")
        .expect("ARM language must define TMode");
    let thumb = ContextSet::single(t_mode, 1);

    let mut reached = project.entry_point().into_iter().collect::<BTreeSet<_>>();
    for function in project.functions().iter() {
        reached.extend(
            function
                .flow_targets(project.blocks())
                .map(|target| target.to().address()),
        );
    }

    let unreached = project
        .functions()
        .iter()
        .filter(|function| !reached.contains(&function.entry()))
        .filter_map(|function| function.entry_with_context(project.blocks()))
        .collect::<Vec<_>>();

    assert!(!unreached.is_empty());
    assert!(unreached.iter().all(|entry| entry.context() == &thumb));
    Ok(())
}

#[test]
fn arm_caller_mode() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/thumb-below-caller.elf")?;
    let engine = AnalysisEngine::new(Project::new_transient(&loader)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let t_mode = project
        .arch()
        .language()
        .context_variable_by_name("TMode")
        .expect("ARM language must define TMode");
    let arm = ContextSet::single(t_mode, 0);
    let thumb = ContextSet::single(t_mode, 1);

    let entry = project.entry_point().expect("fixture has an entry point");
    let caller = project
        .functions()
        .get_by_address(entry)
        .expect("entry function must be recovered");

    for (_, id) in caller.blocks() {
        let block = project
            .blocks()
            .get_by_id(id)
            .expect("caller block must exist");
        assert_eq!(block.context(), &arm, "caller block {}", block.address());
    }

    let calls = caller
        .flow_targets(project.blocks())
        .filter(|target| target.kind().is_call())
        .collect::<Vec<_>>();
    assert!(calls.iter().any(|call| {
        call.to().context() == &thumb && call.to().address() < call.from().address()
    }));
    assert!(calls.iter().any(|call| call.to().context() == &arm));
    Ok(())
}

#[test]
fn function_symbol_modes() -> Result<(), Box<dyn Error>> {
    let loader = Loader::from_file("tests/thumb-mapping-hints.elf")?;
    let engine = AnalysisEngine::new(Project::new_transient(&loader)?)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let t_mode = project
        .arch()
        .language()
        .context_variable_by_name("TMode")
        .expect("ARM language must define TMode");

    for (name, mode) in [("caller", 1), ("callee", 0)] {
        let address = project
            .symbols()
            .iter()
            .find_map(|(_, symbol)| (symbol.symbol() == name).then(|| symbol.address()))
            .expect("fixture must define the function symbol");
        let entry = project
            .functions()
            .get_by_address(address)
            .and_then(|function| function.entry_with_context(project.blocks()))
            .expect("function must be recovered");
        assert_eq!(entry.context(), &ContextSet::single(t_mode, mode), "{name}");
    }
    Ok(())
}

#[test]
fn literal_pool_candidates() -> Result<(), Box<dyn Error>> {
    let bytes = fs::read("tests/libipmi.so")?;
    let elf = object::File::parse(bytes.as_slice())?;
    let text = elf
        .section_by_name(".text")
        .expect("fixture must have a text section")
        .index();
    let mapping_symbols = elf
        .symbols()
        .filter(|symbol| symbol.section_index() == Some(text))
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            name.starts_with('$').then(|| (symbol.address(), name))
        })
        .collect::<BTreeMap<_, _>>();
    let candidates = mapping_symbols
        .iter()
        .zip(mapping_symbols.keys().skip(1))
        .filter(|((start, name), next)| name.starts_with("$d") && **start + 4 < **next)
        .map(|((start, _), _)| start + 4)
        .collect::<Vec<_>>();
    assert!(!candidates.is_empty());

    let loader = Loader::from_file("tests/libipmi.so")?;
    let mut project = Project::new_transient(&loader)?;
    project
        .attributes_mut()
        .set_attr(CANDIDATES_ATTRIBUTE, candidates.clone());
    let engine = AnalysisEngine::new(project)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let recovered = candidates
        .into_iter()
        .map(Address::in_default_space)
        .filter(|address| project.functions().get_by_address(*address).is_some())
        .collect::<Vec<_>>();
    assert!(recovered.is_empty(), "{recovered:?}");
    Ok(())
}

#[test]
fn linear_sweep_arm_mode() -> Result<(), Box<dyn Error>> {
    let bytes = fs::read("tests/thumb-sweep.elf")?;
    let elf = object::File::parse(bytes.as_slice())?;
    let orphan = elf
        .section_by_name("swept")
        .expect("fixture must have a swept section")
        .address();

    let loader = Loader::from_file("tests/thumb-sweep.elf")?;
    let config = AnalysisEngineConfig::default().with_analysis_config(
        FunctionRecoveryConfig::default().with_linear_sweep(LinearSweepConfig::default()),
    );
    let engine = AnalysisEngine::with_config(Project::new_transient(&loader)?, config)?;
    engine.analyse()?;
    let project = engine.into_project()?;

    let t_mode = project
        .arch()
        .language()
        .context_variable_by_name("TMode")
        .expect("ARM language must define TMode");
    let entry = project
        .functions()
        .get_by_address(Address::in_default_space(orphan))
        .and_then(|function| function.entry_with_context(project.blocks()))
        .expect("linear sweep must recover the orphan");
    assert_eq!(entry.context(), &ContextSet::single(t_mode, 0));
    Ok(())
}
