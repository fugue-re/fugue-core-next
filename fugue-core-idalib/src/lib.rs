use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};

use fallible_iterator::FallibleIterator;
use fugue_core::analysis::function::{
    FunctionBuilderContext, FunctionDiscoveryContext, FunctionRecovery, FunctionRecoveryExtension,
};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::{AArch64, Arch, Arm, X86, X86_64};
use fugue_core::engine::AnalysisContext;
use fugue_core::ir::{
    Address, AddressWithContext, FlowKind, RawAddress, SymbolIndex, SymbolProperties,
    SymbolTableSelector, TransientSymbolTable,
};
use fugue_core::lifter::{ContextBitRange, ContextSet, Language};
use fugue_core::loader::{
    ExternalThunkLayout, ImageAddress, ImageLayout, ImageSegment, ImageSegmentContents, Loadable,
    LoadableFromFile, LoadableMetadata, LoaderError,
};
use fugue_core::project::Project;
use fugue_core::storage::{SegmentMappingProvenance, SegmentProperties, DEFAULT_SPACE_ID};
use fugue_core::types::AttributeMap;
use idalib::idb::{IDBOpenOptions, IDB};
use idalib::IDAError;
use thiserror::Error;

pub const ATTRIBUTE_IDA_DATABASE_PATH: &str = "ida.database.path";
pub const ATTRIBUTE_IDA_DATABASE_ANALYSE: &str = "ida.database.analyse";
pub const ATTRIBUTE_IDA_DATABASE_PERSIST: &str = "ida.database.persist";

const FUNCTIONS_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(0);
const NAMES_SELECTOR: SymbolTableSelector = SymbolTableSelector::new(1);
const FUNCTION_HINT_BATCH_SIZE: usize = 1024;
const PROXY_REQUEST_CAPACITY: usize = 8;

#[derive(Debug, Error)]
enum IDAProxyError {
    #[error("IDA proxy disconnected")]
    Disconnected,
    #[error(transparent)]
    Operation(#[from] IDAError),
    #[error("IDA segment not found: {index}")]
    SegmentNotFound { index: usize },
}

struct IDALoader {
    architecture: Arch,
    bank_base: RawAddress,
    external_thunks: Option<ExternalThunkLayout>,
    layout: ImageLayout,
    metadata: LoadableMetadata,
    segment_count: usize,
    symbols: TransientSymbolTable<ImageAddress>,
}

struct IDASegment {
    name: String,
    properties: SegmentProperties,
    provenance: SegmentMappingProvenance,
    size: u64,
    start: u64,
}

struct IDASegmentContents {
    bytes: Vec<u8>,
    external: bool,
    size: usize,
    start: u64,
}

struct IDAFunctionEntry {
    address: u64,
    thumb: bool,
}

struct IDAFunctionEntries {
    entries: Vec<IDAFunctionEntry>,
    next: Option<usize>,
}

struct IDAFunctionBlock {
    indirect: bool,
    last_insn: u64,
    start: u64,
    successors: Vec<u64>,
}

enum IDARequest {
    FunctionBlocks {
        entry: u64,
        reply: SyncSender<Result<Option<Vec<IDAFunctionBlock>>, IDAProxyError>>,
    },
    FunctionEntries {
        cursor: usize,
        limit: usize,
        reply: SyncSender<Result<IDAFunctionEntries, IDAProxyError>>,
    },
    SegmentContents {
        index: usize,
        reply: SyncSender<Result<IDASegmentContents, IDAProxyError>>,
    },
    Segments {
        reply: SyncSender<Result<Vec<IDASegment>, IDAProxyError>>,
    },
    Shutdown,
}

#[derive(fugue_core::AnalysisData)]
struct IDAAnalysis {
    requests: Option<SyncSender<IDARequest>>,
    thread: Option<JoinHandle<()>>,
}

#[derive(fugue_core::AnalysisData)]
pub struct IDABinary {
    #[analysis_data(delegate)]
    analysis: IDAAnalysis,
    architecture: Arch,
    attributes: AttributeMap,
    bank_base: RawAddress,
    external_thunks: Option<ExternalThunkLayout>,
    layout: ImageLayout,
    metadata: LoadableMetadata,
    segment_count: usize,
    symbols: TransientSymbolTable<ImageAddress>,
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

fn ida_loader(database: &IDB) -> Result<IDALoader, LoaderError> {
    let is_32 = database.meta().is_32bit_exactly();
    let is_64 = database.meta().is_64bit();
    if !is_32 && !is_64 {
        return Err(LoaderError::UnsupportedArch);
    }

    let language = ida_language(database)?;
    let architecture = Arch::new(language);
    let (address_symbols, external_thunks) = ida_symbols(&architecture, database)?;

    let mut bank_base = RawAddress::MAX;
    let mut bank_end = RawAddress::zero();
    for (_, segment) in database.segments() {
        bank_base = bank_base.min(segment.start_address().into());
        bank_end = bank_end.max(segment.end_address().into());
    }
    let layout = ImageLayout::single_bank(bank_end.offset().saturating_sub(bank_base.offset()))?;

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

    Ok(IDALoader {
        architecture,
        bank_base,
        external_thunks,
        layout,
        metadata,
        segment_count: database.segment_count(),
        symbols,
    })
}

fn ida_segments(database: &IDB) -> Vec<IDASegment> {
    database
        .segments()
        .map(|(_, segment)| {
            let permissions = segment.permissions();
            let segment_type = segment.r#type();
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
            if segment_type.is_bss() {
                properties |= SegmentProperties::UNINITIALISED;
            }

            IDASegment {
                name: segment.name().unwrap_or_else(|| String::from("LOAD")),
                properties,
                provenance: if segment_type.is_extern() {
                    SegmentMappingProvenance::External
                } else {
                    SegmentMappingProvenance::Segment
                },
                size: segment.end_address().wrapping_sub(segment.start_address()),
                start: segment.start_address(),
            }
        })
        .collect()
}

fn ida_segment_contents(database: &IDB, index: usize) -> Result<IDASegmentContents, IDAProxyError> {
    let segment = database
        .segment_by_id(index)
        .ok_or(IDAProxyError::SegmentNotFound { index })?;
    let start = segment.start_address();
    let size = segment.end_address().wrapping_sub(start) as usize;

    Ok(IDASegmentContents {
        bytes: segment.bytes(),
        external: segment.r#type().is_extern(),
        size,
        start,
    })
}

fn ida_function_entries(database: &IDB, mut cursor: usize, limit: usize) -> IDAFunctionEntries {
    let processor = database.processor();
    let mark_thumb = processor.family().is_arm() && database.meta().is_32bit_exactly();
    let function_count = database.function_count();
    let mut entries = Vec::with_capacity(limit.min(function_count.saturating_sub(cursor)));

    while cursor < function_count && entries.len() < limit {
        let index = cursor;
        cursor += 1;
        let Some(function) = database.function_by_id(index) else {
            continue;
        };
        let address = function.start_address();
        entries.push(IDAFunctionEntry {
            address,
            thumb: mark_thumb && processor.is_thumb_at(address),
        });
    }

    IDAFunctionEntries {
        entries,
        next: (cursor < function_count).then_some(cursor),
    }
}

fn ida_function_blocks(
    database: &IDB,
    entry: u64,
) -> Result<Option<Vec<IDAFunctionBlock>>, IDAProxyError> {
    let Some(function) = database.function_at(entry) else {
        return Ok(None);
    };
    let graph = function.cfg()?;
    let mut blocks = Vec::with_capacity(graph.blocks_count());

    for block in graph.blocks() {
        let mut address = block.start_address();
        let Some((last_insn, indirect)) = (loop {
            let Some(insn) = database.insn_at(address) else {
                break None;
            };
            if insn.is_basic_block_end(false) {
                break Some((insn.address(), insn.is_indirect_jump()));
            }
            let length = insn.len() as u64;
            if length == 0 {
                break None;
            }
            address = address.wrapping_add(length);
            if address >= block.end_address() {
                break None;
            }
        }) else {
            continue;
        };
        let successors = if indirect {
            block
                .succs_with(&graph)
                .map(|successor| successor.start_address())
                .collect()
        } else {
            Vec::new()
        };

        blocks.push(IDAFunctionBlock {
            indirect,
            last_insn,
            start: block.start_address(),
            successors,
        });
    }

    Ok(Some(blocks))
}

fn ida_proxy(
    path: PathBuf,
    database_path: Option<String>,
    analyse: bool,
    persist: bool,
) -> Result<(IDAAnalysis, IDALoader), LoaderError> {
    let (requests, request_receiver) = mpsc::sync_channel(PROXY_REQUEST_CAPACITY);
    let (initialisation_sender, initialisation_receiver) = mpsc::sync_channel(1);
    let thread = thread::Builder::new()
        .name(String::from("ida-proxy"))
        .spawn(move || {
            let result = (|| {
                let mut options = IDBOpenOptions::new();
                options.save(persist).auto_analyse(analyse);
                if let Some(database_path) = database_path {
                    options.idb(database_path);
                }
                let database = options.open(path).map_err(LoaderError::other)?;
                let initialisation = ida_loader(&database)?;
                Ok::<_, LoaderError>((database, initialisation))
            })();

            let (database, initialisation) = match result {
                Ok(result) => result,
                Err(error) => {
                    let _ = initialisation_sender.send(Err(error));
                    return;
                }
            };
            if initialisation_sender.send(Ok(initialisation)).is_err() {
                return;
            }

            while let Ok(request) = request_receiver.recv() {
                match request {
                    IDARequest::FunctionBlocks { entry, reply } => {
                        let _ = reply.send(ida_function_blocks(&database, entry));
                    }
                    IDARequest::FunctionEntries {
                        cursor,
                        limit,
                        reply,
                    } => {
                        let _ = reply.send(Ok(ida_function_entries(&database, cursor, limit)));
                    }
                    IDARequest::SegmentContents { index, reply } => {
                        let _ = reply.send(ida_segment_contents(&database, index));
                    }
                    IDARequest::Segments { reply } => {
                        let _ = reply.send(Ok(ida_segments(&database)));
                    }
                    IDARequest::Shutdown => break,
                }
            }
        })
        .map_err(LoaderError::other)?;

    match initialisation_receiver.recv() {
        Ok(Ok(initialisation)) => Ok((
            IDAAnalysis {
                requests: Some(requests),
                thread: Some(thread),
            },
            initialisation,
        )),
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(error)
        }
        Err(_) => {
            let _ = thread.join();
            Err(LoaderError::other(IDAProxyError::Disconnected))
        }
    }
}

impl IDAAnalysis {
    fn send(&self, request: IDARequest) -> Result<(), IDAProxyError> {
        self.requests
            .as_ref()
            .ok_or(IDAProxyError::Disconnected)?
            .send(request)
            .map_err(|_| IDAProxyError::Disconnected)
    }

    fn function_blocks(
        &self,
        entry: Address,
    ) -> Result<Option<Vec<IDAFunctionBlock>>, IDAProxyError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(IDARequest::FunctionBlocks {
            entry: entry.offset(),
            reply,
        })?;
        response.recv().map_err(|_| IDAProxyError::Disconnected)?
    }

    fn function_entries(
        &self,
        cursor: usize,
        limit: usize,
    ) -> Result<IDAFunctionEntries, IDAProxyError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(IDARequest::FunctionEntries {
            cursor,
            limit,
            reply,
        })?;
        response.recv().map_err(|_| IDAProxyError::Disconnected)?
    }

    fn segment_contents(&self, index: usize) -> Result<IDASegmentContents, IDAProxyError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(IDARequest::SegmentContents { index, reply })?;
        response.recv().map_err(|_| IDAProxyError::Disconnected)?
    }

    fn segments(&self) -> Result<Vec<IDASegment>, IDAProxyError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(IDARequest::Segments { reply })?;
        response.recv().map_err(|_| IDAProxyError::Disconnected)?
    }
}

impl Drop for IDAAnalysis {
    fn drop(&mut self) {
        if let Some(requests) = self.requests.take() {
            let _ = requests.send(IDARequest::Shutdown);
        }

        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                tracing::error!("IDA proxy thread panicked");
            }
        }
    }
}

impl IDABinary {
    pub fn symbols(&self) -> &TransientSymbolTable<ImageAddress> {
        &self.symbols
    }

    pub fn external_thunks(&self) -> Option<&ExternalThunkLayout> {
        self.external_thunks.as_ref()
    }
}

impl LoadableFromFile for IDABinary {
    fn from_file_with(
        path: impl AsRef<Path>,
        attributes: impl Into<AttributeMap>,
    ) -> Result<Self, LoaderError>
    where
        Self: Sized,
    {
        let path = path.as_ref().to_path_buf();
        let attributes = attributes.into();

        let persist = attributes
            .get_attr::<bool>(ATTRIBUTE_IDA_DATABASE_PERSIST)
            .unwrap_or_default();
        let analyse = attributes
            .get_attr::<bool>(ATTRIBUTE_IDA_DATABASE_ANALYSE)
            .unwrap_or(true);
        let database_path = attributes.get_attr::<String>(ATTRIBUTE_IDA_DATABASE_PATH);
        let (analysis, initialisation) = ida_proxy(path, database_path, analyse, persist)?;

        Ok(IDABinary {
            analysis,
            architecture: initialisation.architecture,
            attributes,
            bank_base: initialisation.bank_base,
            external_thunks: initialisation.external_thunks,
            layout: initialisation.layout,
            metadata: initialisation.metadata,
            segment_count: initialisation.segment_count,
            symbols: initialisation.symbols,
        })
    }
}

struct IDAImageContents<'a> {
    binary: &'a IDABinary,
    index: usize,
}

impl<'a> FallibleIterator for IDAImageContents<'a> {
    type Error = LoaderError;
    type Item = ImageSegmentContents<'a>;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.index == self.binary.segment_count {
            return Ok(None);
        }

        let segment = self
            .binary
            .analysis
            .segment_contents(self.index)
            .map_err(LoaderError::other)?;
        self.index += 1;

        let mut bytes = segment.bytes;
        if bytes.len() < segment.size {
            bytes.resize(segment.size, 0);
        }

        if segment.external {
            let address_size = self.binary.architecture.language().address_size();
            let template = self.binary.architecture.external_thunk_template();
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

        Ok(Some(ImageSegmentContents::new(
            segment.start.wrapping_sub(self.binary.bank_base.offset()),
            self.binary.architecture.endian(),
            bytes,
        )))
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
        let segments = match self.analysis.segments() {
            Ok(segments) => segments
                .into_iter()
                .map(move |segment| {
                    Ok(ImageSegment::backed_in_default_bank(
                        segment.name,
                        ImageAddress::in_default_space(segment.start),
                        segment.size,
                        segment.properties,
                        segment.provenance,
                        bank_base,
                    ))
                })
                .collect(),
            Err(error) => vec![Err(LoaderError::other(error))],
        };
        fallible_iterator::convert(segments.into_iter())
    }

    fn image_contents<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = ImageSegmentContents<'a>, Error = LoaderError> + 'a {
        IDAImageContents {
            binary: self,
            index: 0,
        }
    }
}

#[fugue_core::extension]
impl FunctionRecoveryExtension {
    const NAME: &str = "ida";

    fn configure(project: &Project, recovery: &mut FunctionRecovery) -> Result<(), AnalysisError> {
        recovery.add_candidate_discovery_pass(
            "ida-function-discovery",
            IDAFunctionDiscovery::new(project.arch().language()),
        );
        recovery.add_pre_resolution_pass("ida-function-builder", IDAFunctionBuilder);

        Ok(())
    }
}

pub struct IDAFunctionDiscovery {
    t_mode: Option<ContextBitRange>,
}

impl IDAFunctionDiscovery {
    fn new(language: &'static Language) -> Self {
        Self {
            t_mode: language.context_variable_by_name("TMode"),
        }
    }
}

impl AnalysisPass<FunctionDiscoveryContext> for IDAFunctionDiscovery {
    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let Some(analysis) = context.analysis_data.get::<IDAAnalysis>()? else {
            return Ok(());
        };
        let project = &context.project;
        let segms = project.segments();
        let external_bounds = segms
            .iter_views(DEFAULT_SPACE_ID)
            .map_err(|e| AnalysisError::pass_failed("ida-function-discovery", e))?
            .find_map(|view| {
                (view.provenance() == SegmentMappingProvenance::External)
                    .then(|| view.start()..=view.last())
            });

        let mut cursor = 0;
        loop {
            let functions = analysis
                .function_entries(cursor, FUNCTION_HINT_BATCH_SIZE)
                .map_err(|error| AnalysisError::pass_failed("ida-function-discovery", error))?;
            for function in functions.entries {
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

            let Some(next) = functions.next else {
                break;
            };
            cursor = next;
        }

        Ok(())
    }
}

pub struct IDAFunctionBuilder;

impl AnalysisPass<FunctionBuilderContext> for IDAFunctionBuilder {
    fn can_analyse(&self, context: &AnalysisContext<'_, '_>) -> bool {
        !matches!(context.analysis_data.get::<IDAAnalysis>(), Ok(None))
    }

    fn analyse_with(
        &mut self,
        context: &mut AnalysisContext<'_, '_>,
        builder: &mut FunctionBuilderContext,
    ) -> Result<(), AnalysisError> {
        let Some(analysis) = context.analysis_data.get::<IDAAnalysis>()? else {
            return Ok(());
        };
        let entry = builder.entry();
        let Some(blocks) = analysis
            .function_blocks(entry)
            .map_err(|error| AnalysisError::pass_failed("ida-function-builder", error))?
        else {
            return Ok(());
        };

        for block in blocks {
            if block.indirect {
                for successor in block.successors {
                    builder.add_local_target(block.last_insn, successor, FlowKind::IBranch);
                }
            }

            builder.add_candidate(block.start);
        }

        Ok(())
    }
}
