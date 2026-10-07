use std::borrow::Cow;
use std::collections::BTreeMap;
use std::error::Error;
use std::iter;

use fallible_iterator::{FallibleIterator, convert};
use fugue_core::analysis::function::{
    FunctionCandidate, FunctionRecovery, FunctionRecoveryExtension, StructuredFunctionContext,
};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::{Arch, Mips, Mips64, X86_64};
use fugue_core::engine::{AnalysisContext, AnalysisEngine, AnalysisEngineConfig};
use fugue_core::extension;
use fugue_core::ir::{Address, AddressWithContext, RawAddress};
use fugue_core::lifter::{ContextBitRange, ContextHint, ContextSet, Language, RawPCodeOp, Varnode};
use fugue_core::loader::{
    ImageAddress, ImageBacking, ImageLayout, ImageSegment, ImageSegmentContents,
    ImageSegmentContentsIterator, ImageSegmentIterator, Loadable, LoadableMetadata, LoaderError,
};
use fugue_core::project::Project;
use fugue_core::storage::{AddressSpaceId, SegmentMappingProvenance, SegmentProperties};
use fugue_core::types::{AttributeMap, Confidence};

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
                let mapping_hints = self
                    .mapping_hints
                    .iter()
                    .filter_map(|(address, hint)| {
                        translate(*address).map(|address| (address, hint.clone()))
                    })
                    .collect::<BTreeMap<_, _>>();
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
        Mips::resolve_default_variant(true)?,
        Mips::resolve_default_variant(false)?,
        Mips64::resolve_default_variant(true)?,
        Mips64::resolve_default_variant(false)?,
        Mips64::resolve_variant(true, "64-32addr")?,
        Mips64::resolve_variant(false, "64-32addr")?,
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

    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
    let language = Mips::resolve_default_variant(true)?;
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
