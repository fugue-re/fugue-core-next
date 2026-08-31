use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use fallible_iterator::FallibleIterator;
use fugue_core::analysis::function::{
    FunctionBuilderContext, FunctionDiscoveryContext, FunctionRecovery, FunctionRecoveryConfig,
};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::{AArch64, Arch, Arm, X86, X86_64};
use fugue_core::engine::ProjectView;
use fugue_core::ir::{
    Address, AddressWithContext, FlowKind, RawAddress, SymbolIndex, SymbolProperties,
    SymbolTableSelector, TransientSymbolTable,
};
use fugue_core::lifter::{ContextBitRange, ContextSet, Language};
use fugue_core::loader::{
    ExternalThunkLayout, ImageAddress, ImageLayout, ImageSegment, ImageSegmentContents, Loadable,
    LoadableAnalysers, LoadableFromFile, LoadableMetadata, LoaderError,
};
use fugue_core::storage::{SegmentMappingProvenance, SegmentProperties, DEFAULT_SPACE_ID};
use fugue_core::types::AttributeMap;
use idalib::idb::{IDBOpenOptions, IDB};

pub const ATTRIBUTE_IDA_DATABASE_PATH: &str = "ida.database.path";
pub const ATTRIBUTE_IDA_DATABASE_ANALYSE: &str = "ida.database.analyse";
pub const ATTRIBUTE_IDA_DATABASE_PERSIST: &str = "ida.database.persist";

const FUNCTIONS_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);
const NAMES_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(1);

pub struct IDABinary {
    database: Rc<IDB>,
    architecture: Arch,
    symbols: TransientSymbolTable<ImageAddress>,
    external_thunks: Option<ExternalThunkLayout>,
    bank_base: RawAddress,
    layout: ImageLayout,
    mark_thumb: bool,
    metadata: LoadableMetadata,
    attributes: AttributeMap,
}

fn ida_symbols(
    arch: &Arch,
    db: &IDB,
) -> Result<(TransientSymbolTable, Option<ExternalThunkLayout>), LoaderError> {
    let mut symbols = TransientSymbolTable::new();
    let mut external_thunks = db.segment_by_name("extern").map(|segment| {
        let address = segment.start_address();
        let template = arch.external_thunk_template();
        let bounds = address..segment.end_address();
        (
            ExternalThunkLayout::new(
                address,
                arch.language()
                    .address_size()
                    .max(arch.language().address_alignment()),
                template,
            ),
            bounds,
        )
    });

    for (n, fcn) in db.functions() {
        let addr = fcn.start_address();
        let name = fcn.name();
        let props = SymbolProperties::FUNCTION;

        if matches!(external_thunks, Some((_, ref bounds)) if bounds.contains(&fcn.start_address()))
        {
            external_thunks
                .as_mut()
                .expect("external thunk layout exists")
                .0
                .allocate_at(addr)
                .map_err(LoaderError::other)?;
            symbols.insert_extern_with(
                SymbolIndex::new(FUNCTIONS_SELECTOR, n),
                addr,
                name.unwrap_or_default(),
                props,
            );
        } else {
            symbols.insert_local_with(
                SymbolIndex::new(FUNCTIONS_SELECTOR, n),
                addr,
                name.unwrap_or_default(),
                props,
            );
        }
    }

    for (n, name) in db.names().iter().enumerate() {
        let addr = name.address();
        let flags = db.flags_at(addr);

        if !flags.is_data() {
            continue;
        }

        let name = name.name();

        if matches!(external_thunks, Some((_, ref bounds)) if bounds.contains(&addr)) {
            external_thunks
                .as_mut()
                .expect("external thunk layout exists")
                .0
                .allocate_at(addr)
                .map_err(LoaderError::other)?;
            symbols.insert_extern_with(
                SymbolIndex::new(NAMES_SELECTOR, n),
                addr,
                name,
                SymbolProperties::DATA,
            );
        } else {
            symbols.insert(
                SymbolIndex::new(NAMES_SELECTOR, n),
                addr,
                name,
                SymbolProperties::DATA,
            );
        }
    }

    Ok((
        symbols,
        external_thunks.map(|(external_thunks, _)| external_thunks),
    ))
}

fn ida_language(database: &IDB) -> Result<&'static Language, LoaderError> {
    let processor = database.processor();
    let is_32 = database.meta().is_32bit_exactly();
    let is_64 = database.meta().is_64bit();
    let is_be = database.meta().is_be();

    if processor.family().is_arm() && is_64 {
        return Ok(AArch64::resolve_default_variant(is_be)?);
    }

    if processor.family().is_arm() && is_32 {
        let is_thumb =
            matches!(database.meta().start_address(), Some(addr) if processor.is_thumb_at(addr));
        return Ok(if is_thumb {
            Arm::resolve_variant(is_be, "v8T")?
        } else {
            Arm::resolve_default_variant(is_be)?
        });
    }

    if processor.family().is_386() {
        return Ok(if is_32 {
            X86::resolve_default_variant()?
        } else {
            X86_64::resolve_default_variant()?
        });
    }

    Err(LoaderError::UnsupportedArch)
}

impl IDABinary {
    pub fn database(&self) -> &IDB {
        &self.database
    }

    pub fn symbols(&self) -> &TransientSymbolTable<ImageAddress> {
        &self.symbols
    }

    pub fn external_thunks(&self) -> Option<&ExternalThunkLayout> {
        self.external_thunks.as_ref()
    }
}

impl LoadableFromFile for IDABinary {
    fn from_file_with(
        path: impl AsRef<std::path::Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        let path = path.as_ref();
        let attributes = attributes.into();

        let mut database_opts = IDBOpenOptions::new();

        let persist = attributes
            .get_attr::<bool>(ATTRIBUTE_IDA_DATABASE_PERSIST)
            .unwrap_or_default();

        database_opts.save(persist);

        let analyse = attributes
            .get_attr::<bool>(ATTRIBUTE_IDA_DATABASE_ANALYSE)
            .unwrap_or(true);

        database_opts.auto_analyse(analyse);

        if let Some(idb) = attributes.get_attr::<String>(ATTRIBUTE_IDA_DATABASE_PATH) {
            database_opts.idb(idb);
        }

        let database = database_opts.open(path).map_err(LoaderError::other)?;
        let processor = database.processor();

        let is_32 = database.meta().is_32bit_exactly();
        let is_64 = database.meta().is_64bit();

        if !is_32 && !is_64 {
            return Err(LoaderError::UnsupportedArch);
        }

        let mark_thumb = processor.family().is_arm() && is_32;

        let language = ida_language(&database)?;
        let architecture = Arch::new(language);

        let (address_symbols, external_thunks) = ida_symbols(&architecture, &database)?;

        let mut bank_base = RawAddress::MAX;
        let mut bank_end = RawAddress::zero();
        for (_, segm) in database.segments() {
            bank_base = bank_base.min(segm.start_address().into());
            bank_end = bank_end.max(segm.end_address().into());
        }
        let layout =
            ImageLayout::single_bank(bank_end.offset().saturating_sub(bank_base.offset()))?;

        let mut symbols = TransientSymbolTable::<ImageAddress>::new();
        for (index, _, symbol) in address_symbols.iter_by_index() {
            symbols.insert(
                index,
                ImageAddress::in_default_space(symbol.address().offset()),
                symbol.symbol(),
                symbol.properties(),
            );
        }

        let version = idalib::version().map_err(LoaderError::other)?;

        let metadata = LoadableMetadata::from_hashes_with(
            database.meta().input_file_md5(),
            database.meta().input_file_sha256(),
            database.meta().input_file_path(),
            format!(
                "IDA Pro v{}.{}.{} Loader",
                version.major(),
                version.minor(),
                version.build()
            ),
        );

        Ok(IDABinary {
            database: Rc::new(database),
            architecture,
            symbols,
            external_thunks,
            bank_base,
            layout,
            mark_thumb,
            metadata,
            attributes,
        })
    }
}

impl Loadable for IDABinary {
    fn architecture(&self) -> Arch {
        self.architecture.clone()
    }

    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn metadata(&self) -> &LoadableMetadata {
        &self.metadata
    }

    fn image_symbols(&self) -> Option<&TransientSymbolTable<ImageAddress>> {
        Some(&self.symbols)
    }

    fn image_layout(&self) -> &ImageLayout {
        &self.layout
    }

    fn image_segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegment<'a>, Error = LoaderError> + 'a {
        let bank_base = self.bank_base;

        fallible_iterator::convert(self.database.segments().map(move |(_, segm)| {
            let start = segm.start_address();
            let size = segm.end_address().wrapping_sub(start);
            let name = segm.name().unwrap_or_else(|| String::from("LOAD"));
            let permissions = segm.permissions();
            let type_ = segm.r#type();

            let mut properties = SegmentProperties::default();

            if permissions.is_readable() {
                properties |= SegmentProperties::PERM_READ;
            }

            if permissions.is_writable() {
                properties |= SegmentProperties::PERM_WRITE;
            }

            if permissions.is_executable() {
                properties |= SegmentProperties::PERM_EXECUTE;
            }

            if type_.is_bss() {
                properties |= SegmentProperties::UNINITIALISED;
            }

            let provenance = if type_.is_extern() {
                SegmentMappingProvenance::External
            } else {
                SegmentMappingProvenance::Segment
            };

            Ok(ImageSegment::backed_in_default_bank(
                name,
                ImageAddress::in_default_space(start),
                size,
                properties,
                provenance,
                bank_base,
            ))
        }))
    }

    fn image_contents<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a {
        let bank_base = self.bank_base.offset();
        let endian = self.architecture.endian();
        let address_size = self.architecture.language().address_size();
        let template = self.architecture.external_thunk_template();

        fallible_iterator::convert(self.database.segments().map(move |(_, segm)| {
            let start = segm.start_address();
            let size = segm.end_address().wrapping_sub(start) as usize;
            let type_ = segm.r#type();

            let mut bytes = segm.bytes();

            if bytes.len() < size {
                bytes.resize(size, 0);
            }

            if type_.is_extern() {
                let template_size = template.size();
                let aligned_template_size = template_size.next_multiple_of(address_size);

                if aligned_template_size > address_size {
                    tracing::warn!(
                        "external thunk template is larger than available space in external segment; skipping"
                    );
                } else {
                    for chunk in bytes.chunks_exact_mut(aligned_template_size) {
                        chunk[..template_size].copy_from_slice(template.bytes());
                    }
                }
            }

            Ok(ImageSegmentContents::new(
                start.wrapping_sub(bank_base),
                endian,
                bytes,
            ))
        }))
    }
}

pub struct IDAAnalysers<'a> {
    binary: &'a IDABinary,
}

#[derive(Clone)]
struct IDAFunctionFacts {
    blocks: Arc<BTreeMap<u64, Arc<[IDABlockHint]>>>,
    functions: Arc<[IDAFunctionHint]>,
}

#[derive(Clone, Copy)]
struct IDAFunctionHint {
    address: u64,
    thumb: bool,
}

#[derive(Clone)]
struct IDABlockHint {
    start: u64,
    last_insn: u64,
    indirect: bool,
    successors: Arc<[u64]>,
}

impl IDAFunctionFacts {
    fn new(binary: &IDABinary) -> Self {
        let database = binary.database();
        let processor = database.processor();
        let mut functions = Vec::new();
        let mut blocks = BTreeMap::new();

        for (_, function) in database.functions() {
            let entry = function.start_address();
            functions.push(IDAFunctionHint {
                address: entry,
                thumb: binary.mark_thumb && processor.is_thumb_at(entry),
            });

            let Ok(cfg) = function.cfg() else {
                continue;
            };

            let mut block_hints = Vec::new();
            for block in cfg.blocks() {
                let Some((last_insn, indirect)) =
                    Self::last_block_instruction(database, block.start_address())
                else {
                    continue;
                };
                let successors = if indirect {
                    block
                        .succs_with(&cfg)
                        .map(|successor| successor.start_address())
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                block_hints.push(IDABlockHint {
                    start: block.start_address(),
                    last_insn,
                    indirect,
                    successors: successors.into(),
                });
            }

            blocks.insert(entry, block_hints.into());
        }

        Self {
            blocks: Arc::new(blocks),
            functions: functions.into(),
        }
    }

    fn last_block_instruction(database: &IDB, start: u64) -> Option<(u64, bool)> {
        let mut address = start;
        loop {
            let insn = database.insn_at(address)?;
            if insn.is_basic_block_end(false) {
                return Some((insn.address(), insn.is_indirect_jump()));
            }
            address += insn.len() as u64;
        }
    }

    fn blocks(&self, entry: Address) -> Option<&[IDABlockHint]> {
        self.blocks
            .get(&entry.offset())
            .map(|blocks| blocks.as_ref())
    }
}

impl<'a> LoadableAnalysers for IDAAnalysers<'a> {
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery, AnalysisError> {
        let mut recovery = FunctionRecovery::new_with(
            config
                .with_segment_function_hints(false)
                .with_symbol_table_function_hints(false),
        );

        let facts = IDAFunctionFacts::new(self.binary);

        recovery.add_candidate_discovery_pass(
            "ida-function-discovery",
            IDAFunctionDiscovery::new(
                &facts,
                self.binary.architecture.language(),
                self.binary.mark_thumb,
            ),
        );

        recovery.add_builder_initialisation_pass(
            "ida-function-builder",
            IDAFunctionBuilder::new(&facts),
        );

        Ok(recovery)
    }
}

pub struct IDAFunctionDiscovery {
    facts: IDAFunctionFacts,
    t_mode: Option<ContextBitRange>,
}

impl IDAFunctionDiscovery {
    fn new(facts: &IDAFunctionFacts, language: &'static Language, mark_thumb: bool) -> Self {
        let t_mode = mark_thumb
            .then(|| language.context_variable_by_name("TMode"))
            .flatten();
        Self {
            facts: facts.clone(),
            t_mode,
        }
    }
}

impl AnalysisPass<FunctionDiscoveryContext> for IDAFunctionDiscovery {
    fn analyse_with(
        &mut self,
        project: &ProjectView<'_>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let segms = project.segments();
        let external_bounds = segms
            .iter_views(DEFAULT_SPACE_ID)
            .map_err(|e| AnalysisError::pass_failed("ida-function-discovery", e))?
            .find_map(|view| {
                (view.provenance() == SegmentMappingProvenance::External)
                    .then(|| view.start()..=view.last())
            });

        for function in self.facts.functions.iter() {
            let addr = Address::from(function.address);

            if state.functions().contains_key(&addr) {
                continue;
            }

            if matches!(external_bounds, Some(ref bounds) if bounds.contains(&addr)) {
                continue;
            }

            if let Some(t_mode) = self.t_mode {
                let value = u32::from(function.thumb);
                state.add_candidate(AddressWithContext::new(
                    addr,
                    ContextSet::single(t_mode, value),
                ));
            } else {
                state.add_candidate(addr);
            }
        }

        Ok(())
    }
}

pub struct IDAFunctionBuilder {
    facts: IDAFunctionFacts,
}

impl IDAFunctionBuilder {
    fn new(facts: &IDAFunctionFacts) -> Self {
        Self {
            facts: facts.clone(),
        }
    }
}

impl AnalysisPass<FunctionBuilderContext> for IDAFunctionBuilder {
    fn analyse_with(
        &mut self,
        _project: &ProjectView<'_>,
        builder: &mut FunctionBuilderContext,
    ) -> Result<(), AnalysisError> {
        let entry = builder.entry();
        let Some(blocks) = self.facts.blocks(entry) else {
            return Ok(());
        };

        for block in blocks {
            if block.indirect {
                for successor in block.successors.iter().copied() {
                    builder.add_local_target(block.last_insn, successor, FlowKind::IBranch);
                }
            }

            builder.add_candidate(block.start);
        }

        Ok(())
    }
}
