use fallible_iterator::FallibleIterator;

use fugue_core::analysis::core::functions::{FunctionBuilderContext, FunctionRecovery};
use fugue_core::analysis::{AnalysisError, AnalysisPass};
use fugue_core::arch::Arch;
use fugue_core::entities::flow_graph::FlowKind;
use fugue_core::lifter::arm::context::T_MODE;
use fugue_core::lifter::{ContextSet, LanguageVariant};
use fugue_core::loader::symbols::SymbolProperties;
use fugue_core::loader::{
    ExternSymbols, Loadable, LoadableFromFile, LoadableSegment, LoaderError, LocalSymbols,
};
use fugue_core::memory::SegmentProperties;
use fugue_core::project::Project;
use fugue_core::types::{Address, AttributeMap};

use idalib::idb::{IDBOpenOptions, IDB};

pub const ATTRIBUTE_IDA_DATABASE_PATH: &str = "ida.database.path";

pub struct IDABinary {
    database: IDB,
    architecture: Arch,
    local_symbols: LocalSymbols,
    extern_symbols: Option<ExternSymbols>,
    mark_thumb: bool,
    attributes: AttributeMap,
}

fn ida_symbols(arch: &Arch, db: &IDB) -> (LocalSymbols, Option<ExternSymbols>) {
    let mut locals = LocalSymbols::new();
    let mut externs = db.segment_by_name("extern").map(|segm| {
        let addr = segm.start_address();
        let templ = arch.external_thunk_template();
        let bounds = addr..segm.end_address();
        (
            ExternSymbols::new(addr, arch.language().address_size(), templ),
            bounds,
        )
    });

    // TODO: implement names API for globals

    for (n, fcn) in db.functions() {
        let addr = fcn.start_address();
        let name = fcn.name().map(|s| s.into());
        let props = SymbolProperties::FUNCTION;

        if matches!(externs, Some((_, ref bounds)) if bounds.contains(&fcn.start_address())) {
            externs
                .as_mut()
                .unwrap()
                .0
                .add_symbol_with(n, addr, name, props);
        } else {
            locals.add_symbol_with(n, addr, name, props);
        }
    }

    (locals, externs.map(|(symbols, _)| symbols))
}

fn ida_language(database: &IDB) -> Result<LanguageVariant, LoaderError> {
    let processor = database.processor();
    let is_32 = database.meta().is_32bit_exactly();
    let is_64 = database.meta().is_64bit();
    let is_be = database.meta().is_be();

    if processor.family().is_arm() && is_64 {
        return Ok(if is_be {
            fugue_core::lifter::aarch64::be::variants::DEFAULT
        } else {
            fugue_core::lifter::aarch64::le::variants::DEFAULT
        });
    }

    if processor.family().is_arm() && is_32 {
        let is_thumb =
            matches!(database.meta().start_address(), Some(addr) if processor.is_thumb_at(addr));
        return Ok(if is_be {
            if is_thumb {
                fugue_core::lifter::arm::be::variants::DEFAULT_THUMB
            } else {
                fugue_core::lifter::arm::be::variants::DEFAULT
            }
        } else {
            if is_thumb {
                fugue_core::lifter::arm::le::variants::DEFAULT_THUMB
            } else {
                fugue_core::lifter::arm::le::variants::DEFAULT
            }
        });
    }

    if processor.family().is_386() {
        return Ok(if is_32 {
            fugue_core::lifter::x86::variants::DEFAULT
        } else {
            fugue_core::lifter::x86_64::variants::DEFAULT
        });
    }

    if processor.family().is_386() && is_64 {
        return Ok(fugue_core::lifter::x86_64::variants::DEFAULT);
    }

    Err(LoaderError::UnsupportedArch)
}

impl IDABinary {
    pub fn database(&self) -> &IDB {
        &self.database
    }

    pub fn locals(&self) -> &LocalSymbols {
        &self.local_symbols
    }

    pub fn externs(&self) -> Option<&ExternSymbols> {
        self.extern_symbols.as_ref()
    }

    pub fn function_recovery_pass(&self) -> IDAFunctionRecovery {
        IDAFunctionRecovery::new(&self.database, self.mark_thumb)
    }

    pub fn function_builder_pass(&self) -> IDAFunctionBuilder {
        IDAFunctionBuilder::new(&self.database)
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

        database_opts.save(true);
        database_opts.auto_analyse(true);

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

        let (local_symbols, extern_symbols) = ida_symbols(&architecture, &database);

        Ok(IDABinary {
            database,
            architecture,
            local_symbols,
            extern_symbols,
            mark_thumb,
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

    fn entry(&self) -> Option<Address> {
        self.database.meta().start_address().map(Address::from)
    }

    fn local_symbols(&self) -> Option<&LocalSymbols> {
        Some(&self.local_symbols)
    }

    fn extern_symbols(&self) -> Option<&ExternSymbols> {
        self.extern_symbols.as_ref()
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
                    tracing::trace!("patching extern segment with external thunk template ({} bytes)", aligned_template_len);
                    for chunk in bytes.chunks_exact_mut(aligned_template_len) {
                        chunk[..template_len].copy_from_slice(template.bytes());
                    }
                }
            }

            Ok(LoadableSegment::from_parts(name, start, properties, bytes))
        }))
    }
}

pub struct IDAFunctionRecovery<'a> {
    database: &'a IDB,
    mark_thumb: bool,
}

impl<'a> IDAFunctionRecovery<'a> {
    pub fn new(database: &'a IDB, mark_thumb: bool) -> Self {
        IDAFunctionRecovery {
            database,
            mark_thumb,
        }
    }
}

impl<'a> AnalysisPass<'a, FunctionRecovery<'a>> for IDAFunctionRecovery<'a> {
    fn analyse_with(
        &mut self,
        project: &mut Project,
        state: &mut FunctionRecovery,
    ) -> Result<(), AnalysisError> {
        let extern_bounds = project.extern_symbols().map(|externs| externs.bounds());
        for (_, f) in self.database.functions() {
            let addr = Address::from(f.start_address());
            if matches!(extern_bounds, Some(ref bounds) if bounds.contains(&addr)) {
                continue;
            }

            if self.mark_thumb {
                let context = if self.database.processor().is_thumb_at(f.start_address()) {
                    ContextSet::single(T_MODE, 1)
                } else {
                    ContextSet::single(T_MODE, 0)
                };

                state.add_candidate_with_context(addr, context);
            } else {
                state.add_candidate(addr);
            }
        }
        Ok(())
    }
}

pub struct IDAFunctionBuilder<'a> {
    database: &'a IDB,
}

impl<'a> IDAFunctionBuilder<'a> {
    pub fn new(database: &'a IDB) -> Self {
        IDAFunctionBuilder { database }
    }
}

impl<'a> AnalysisPass<'a, FunctionBuilderContext> for IDAFunctionBuilder<'a> {
    fn analyse_with(
        &mut self,
        _project: &mut Project,
        builder: &mut FunctionBuilderContext,
    ) -> Result<(), AnalysisError> {
        let entry = builder.entry();
        let Some(f) = self.database.function_at(entry.into()) else {
            return Ok(());
        };

        let Ok(cfg) = f.cfg() else {
            return Ok(());
        };

        let last_insns = cfg
            .blocks()
            .map(|b| {
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
            })
            .collect::<Vec<_>>();

        for (i, block) in cfg.blocks().enumerate() {
            let (last_insn, is_indirect) = last_insns[i];

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
