use std::rc::Rc;

use fallible_iterator::FallibleIterator;

use fugue_core::analysis::core::FunctionRecoveryConfig;
use fugue_core::analysis::function::recovery::analysis::FunctionDiscoveryContext;
use fugue_core::analysis::function::recovery::{FunctionBuilderContext, FunctionRecovery};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::arm::context::T_MODE;
use fugue_core::arch::Arch;
use fugue_core::ir::{
    Address, AddressWithContext, ExternSegment, FlowKind, IndexedSymbolTable, SegmentProperties,
    SymbolIndex, SymbolProperties,
};
use fugue_core::lifter::{ContextSet, LanguageVariant};
use fugue_core::loader::{
    Loadable, LoadableAnalysers, LoadableFromFile, LoadableMetadata, LoadableSegment, LoaderError,
};
use fugue_core::project::Project;
use fugue_core::storage::ProjectStorageProvider;
use fugue_core::types::AttributeMap;

use idalib::idb::{IDBOpenOptions, IDB};

pub const ATTRIBUTE_IDA_DATABASE_PATH: &str = "ida.database.path";
pub const ATTRIBUTE_IDA_DATABASE_ANALYSE: &str = "ida.database.analyse";
pub const ATTRIBUTE_IDA_DATABASE_PERSIST: &str = "ida.database.persist";

const FUNCTIONS_SELECTOR: usize = 0;
const NAMES_SELECTOR: usize = 1;

pub struct IDABinary {
    database: Rc<IDB>,
    architecture: Arch,
    symbols: IndexedSymbolTable,
    extern_segm: Option<ExternSegment>,
    mark_thumb: bool,
    metadata: LoadableMetadata,
    attributes: AttributeMap,
}

fn ida_symbols(
    arch: &Arch,
    db: &IDB,
) -> Result<(IndexedSymbolTable, Option<ExternSegment>), LoaderError> {
    let mut symbols = IndexedSymbolTable::new();
    let mut externs = db.segment_by_name("extern").map(|segm| {
        let addr = segm.start_address();
        let templ = arch.external_thunk_template();
        let bounds = addr..segm.end_address();
        (
            ExternSegment::new(
                addr,
                arch.language()
                    .address_size()
                    .max(arch.language().address_alignment()),
                templ,
            ),
            bounds,
        )
    });

    for (n, fcn) in db.functions() {
        let addr = fcn.start_address();
        let name = fcn.name();
        let props = SymbolProperties::FUNCTION;

        if matches!(externs, Some((_, ref bounds)) if bounds.contains(&fcn.start_address())) {
            externs
                .as_mut()
                .expect("extern segment exists")
                .0
                .add_extern_at(addr)
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

        if matches!(externs, Some((_, ref bounds)) if bounds.contains(&addr)) {
            externs
                .as_mut()
                .expect("extern segment exists")
                .0
                .add_extern_at(addr)
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

    Ok((symbols, externs.map(|(symbols, _)| symbols)))
}

fn ida_language(database: &IDB) -> Result<LanguageVariant, LoaderError> {
    let processor = database.processor();
    let is_32 = database.meta().is_32bit_exactly();
    let is_64 = database.meta().is_64bit();
    let is_be = database.meta().is_be();

    if processor.family().is_arm() && is_64 {
        return Ok(if is_be {
            fugue_core::arch::aarch64::be::variants::DEFAULT
        } else {
            fugue_core::arch::aarch64::le::variants::DEFAULT
        });
    }

    if processor.family().is_arm() && is_32 {
        let is_thumb =
            matches!(database.meta().start_address(), Some(addr) if processor.is_thumb_at(addr));
        return Ok(if is_be {
            if is_thumb {
                fugue_core::arch::arm::be::variants::DEFAULT_THUMB
            } else {
                fugue_core::arch::arm::be::variants::DEFAULT
            }
        } else {
            if is_thumb {
                fugue_core::arch::arm::le::variants::DEFAULT_THUMB
            } else {
                fugue_core::arch::arm::le::variants::DEFAULT
            }
        });
    }

    if processor.family().is_386() {
        return Ok(if is_32 {
            fugue_core::arch::x86::variants::DEFAULT
        } else {
            fugue_core::arch::x86_64::variants::DEFAULT
        });
    }

    if processor.family().is_386() && is_64 {
        return Ok(fugue_core::arch::x86_64::variants::DEFAULT);
    }

    Err(LoaderError::UnsupportedArch)
}

impl IDABinary {
    pub fn database(&self) -> &IDB {
        &self.database
    }

    pub fn symbols(&self) -> &IndexedSymbolTable {
        &self.symbols
    }

    pub fn extern_segment(&self) -> Option<&ExternSegment> {
        self.extern_segm.as_ref()
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

        let (symbols, extern_segm) = ida_symbols(&architecture, &database)?;

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
            extern_segm,
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

    fn symbols(&self) -> Option<&IndexedSymbolTable> {
        Some(&self.symbols)
    }

    fn segment_range(&self) -> (Address, Address) {
        let mut start = Address::MAX;
        let mut end = Address::zero();

        for (_, segm) in self.database.segments() {
            start = start.min(segm.start_address().into());
            end = end.max(segm.end_address().wrapping_sub(1).into());
        }

        (start, end)
    }

    fn segments<'a>(
        &'a self,
    ) -> impl FallibleIterator<Item = LoadableSegment<'a>, Error = LoaderError> + 'a {
        // NOTE: we take all segments verbatim from IDA except the extern segment; we
        // opt to patch each entry with the architecture's "external function template",
        // which amounts to a return instruction, and hence fits in the space available
        // for all architectures we support.

        let address_size = self.architecture.language().address_size();

        fallible_iterator::convert(self.database.segments().map(move |(_, segm)| {
            let start = Address::from(segm.start_address());
            let end = Address::from(segm.end_address().wrapping_sub(1));
            let size = usize::from(end - start) + 1;

            tracing::trace!("loading segment {start}-{end}");

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

            let mut bytes = segm.bytes();

            if bytes.len() < size {
                bytes.resize(size, 0);
            }

            if type_.is_extern() {
                properties |= SegmentProperties::EXTERNAL;

                let template = self.architecture.external_thunk_template();
                let template_len = template.len();
                let aligned_template_len =
                    template_len.next_multiple_of(address_size);

                if aligned_template_len > address_size {
                    tracing::warn!("external thunk template is larger than available space in extern segment; skipping");
                } else {
                    tracing::trace!("patching extern segment with external thunk template ({aligned_template_len} bytes)");
                    for chunk in bytes.chunks_exact_mut(aligned_template_len) {
                        chunk[..template_len].copy_from_slice(template.bytes());
                    }
                }
            }

            Ok(LoadableSegment::new(name, start, properties, bytes))
        }))
    }
}

pub struct IDAAnalysers<'a> {
    binary: &'a IDABinary,
}

impl<'a, P> LoadableAnalysers<P> for IDAAnalysers<'a>
where
    P: ProjectStorageProvider,
{
    fn function_recovery_with(
        &self,
        config: FunctionRecoveryConfig,
    ) -> Result<FunctionRecovery<P>, AnalysisError> {
        let mut recovery = FunctionRecovery::new_with(
            config
                .with_segment_function_hints(false)
                .with_symbol_table_function_hints(false),
        );

        recovery.add_candidate_discovery_pass(
            "ida-function-discovery",
            IDAFunctionDiscovery::new(self.binary, self.binary.mark_thumb),
        );

        recovery.add_builder_initialisation_pass(
            "ida-function-builder",
            IDAFunctionBuilder::new(self.binary),
        );

        Ok(recovery)
    }
}

pub struct IDAFunctionDiscovery {
    database: Rc<IDB>,
    mark_thumb: bool,
}

impl IDAFunctionDiscovery {
    pub fn new(database: &IDABinary, mark_thumb: bool) -> Self {
        Self {
            database: database.database.clone(),
            mark_thumb,
        }
    }
}

impl<P> AnalysisPass<P, FunctionDiscoveryContext> for IDAFunctionDiscovery
where
    P: ProjectStorageProvider,
{
    fn analyse_with(
        &mut self,
        project: &mut Project<P>,
        state: &mut FunctionDiscoveryContext,
    ) -> Result<(), AnalysisError> {
        let segms = project.segments();
        let extern_bounds = segms
            .iter_views()
            .map_err(|e| AnalysisError::pass_failed("ida-function-discovery", e))?
            .find_map(|view| {
                view.properties()
                    .contains(SegmentProperties::EXTERNAL)
                    .then(|| view.start()..=view.last())
            });

        for (_, f) in self.database.functions() {
            let addr = Address::from(f.start_address());

            if state.functions().contains_key(&addr) {
                continue;
            }

            if matches!(extern_bounds, Some(ref bounds) if bounds.contains(&addr)) {
                continue;
            }

            if self.mark_thumb {
                let context = if self.database.processor().is_thumb_at(f.start_address()) {
                    ContextSet::single(T_MODE, 1)
                } else {
                    ContextSet::single(T_MODE, 0)
                };

                state.add_candidate(AddressWithContext::new(addr, context));
            } else {
                state.add_candidate(addr);
            }
        }

        Ok(())
    }
}

pub struct IDAFunctionBuilder {
    database: Rc<IDB>,
    last_insns: Vec<(u64, bool)>,
}

impl IDAFunctionBuilder {
    pub fn new(binary: &IDABinary) -> Self {
        IDAFunctionBuilder {
            database: binary.database.clone(),
            last_insns: Vec::new(),
        }
    }
}

impl<P> AnalysisPass<P, FunctionBuilderContext> for IDAFunctionBuilder
where
    P: ProjectStorageProvider,
{
    fn analyse_with(
        &mut self,
        _project: &mut Project<P>,
        builder: &mut FunctionBuilderContext,
    ) -> Result<(), AnalysisError> {
        let entry = builder.entry();
        let Some(f) = self.database.function_at(entry.into()) else {
            return Ok(());
        };

        let Ok(cfg) = f.cfg() else {
            return Ok(());
        };

        self.last_insns.clear();
        self.last_insns.reserve(cfg.blocks_count());

        self.last_insns.extend(cfg.blocks().map(|b| {
            let mut addr = b.start_address();
            loop {
                let insn = self
                    .database
                    .insn_at(addr.into())
                    .expect("valid instruction");
                if insn.is_basic_block_end(false) {
                    return (insn.address(), insn.is_indirect_jump());
                }
                addr += insn.len() as u64;
            }
        }));

        for (i, block) in cfg.blocks().enumerate() {
            let (last_insn, is_indirect) = self.last_insns[i];

            // NOTE: concrete edges will be automatically resolved, so we only use IDA's
            // edges to hint at indirect flows, e.g., jump tables, etc.
            if is_indirect {
                for succ in block.succs_with(&cfg) {
                    // TODO: classify edges correctly
                    builder.add_local_target(last_insn, succ.start_address(), FlowKind::IBranch);
                }
            }

            builder.add_candidate(block.start_address());
        }

        Ok(())
    }
}
