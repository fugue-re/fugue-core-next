use fallible_iterator::FallibleIterator;

use fugue_base::analysis::core::functions::{FunctionBuilder, FunctionRecovery};
use fugue_base::analysis::{AnalysisError, AnalysisPass};
use fugue_base::arch::Arch;
use fugue_base::entities::flow_graph::FlowKind;
use fugue_base::lifter::arm::le::context::T_MODE;
use fugue_base::lifter::{ContextSet, Language, Lifter, LifterBuilder};
use fugue_base::loader::symbols::SymbolProperties;
use fugue_base::loader::{
    ExternSymbols, Loadable, LoadableFromFile, LoadableSegment, LoaderError, LocalSymbols,
};
use fugue_base::memory::SegmentProperties;
use fugue_base::project::Project;
use fugue_base::types::{Address, AttributeMap};

use idalib::idb::{IDBOpenOptions, IDB};

pub struct IDABinary {
    database: IDB,
    architecture: Arch,
    lifter: Lifter,
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
            ExternSymbols::new(addr, arch.language().address_alignment(), templ),
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

    pub fn function_recovery_pass(
        &self,
    ) -> IDAFunctionRecovery {
        IDAFunctionRecovery::new(&self.database, self.mark_thumb)
    }

    pub fn function_builder_pass(
        &self,
    ) -> IDAFunctionBuilder {
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

        database_opts.save(false);
        database_opts.auto_analyse(true);

        if let Some(idb) = attributes.get_attr::<String>("idb.path") {
            database_opts.idb(idb);
        }

        let database = database_opts.open(path).map_err(LoaderError::other)?;
        let processor = database.processor();

        let is_32 = database.meta().is_32bit_exactly();
        let is_64 = database.meta().is_64bit();

        if !is_32 && !is_64 {
            return Err(LoaderError::UnsupportedArch);
        }

        let mark_thumb = processor.family().is_arm() && !is_64;

        let builder = if processor.family().is_arm() {
            if is_64 {
                LifterBuilder::new("AARCH64").bits(64)
            } else if matches!(database.meta().start_address(), Some(addr) if processor.is_thumb_at(addr))
            {
                LifterBuilder::new("ARM").bits(32).variant("v8T")
            } else {
                LifterBuilder::new("ARM").bits(32)
            }
        } else if processor.family().is_386() {
            if is_64 {
                LifterBuilder::new("x86").bits(64)
            } else {
                LifterBuilder::new("x86").bits(32)
            }
        } else {
            return Err(LoaderError::UnsupportedArch);
        };

        let lifter = builder.build().map_err(LoaderError::other)?;
        let architecture = Arch::new(lifter.language());

        let (local_symbols, extern_symbols) = ida_symbols(&architecture, &database);

        Ok(IDABinary {
            database,
            architecture,
            lifter,
            local_symbols,
            extern_symbols,
            mark_thumb,
            attributes,
        })
    }
}

impl Loadable for IDABinary {
    fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        &mut self.attributes
    }

    fn entry(&self) -> Option<Address> {
        self.database.meta().start_address().map(Address::from)
    }

    fn language(&self) -> &'static Language {
        self.lifter.language()
    }

    fn lifter(&self) -> Lifter {
        self.lifter.clone()
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

        let address_size = self.lifter.address_size();

        fallible_iterator::convert(self.database.segments().map(move |(_, segm)| {
            let start = Address::from(segm.start_address());
            let end = Address::from(segm.end_address().wrapping_sub(1));

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

            if type_.is_extern() {
                properties |= SegmentProperties::EXTERNAL;

                let template = self.architecture.external_thunk_template();
                let template_len = template.len();
                let aligned_template_len =
                    template_len.next_multiple_of(address_size);

                if aligned_template_len > address_size {
                    tracing::warn!("external thunk template is larger than available space in extern segment; skipping");
                } else {
                    tracing::trace!("patching extern segment with external thunk template");
                    for chunk in bytes.chunks_exact_mut(aligned_template_len) {
                        chunk[..template_len].copy_from_slice(template.bytes());
                    }
                }
            }

            Ok(LoadableSegment::from_parts(name, start, properties, segm.bytes()))
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

impl<'a> AnalysisPass<'a, FunctionRecovery> for IDAFunctionRecovery<'a> {
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

impl<'a> AnalysisPass<'a, FunctionBuilder> for IDAFunctionBuilder<'a> {
    fn analyse_with(
        &mut self,
        _project: &mut Project,
        builder: &mut FunctionBuilder,
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
                        return insn.address();
                    }
                    addr += insn.len() as u64;
                }
            })
            .collect::<Vec<_>>();

        for (i, block) in cfg.blocks().enumerate() {
            let last_insn = last_insns[i];
            for succ in block.succs_with(&cfg) {
                // TODO: classify edges correctly
                builder.add_local_target(last_insn, succ.start_address(), FlowKind::Branch);
            }

            builder.add_candidate(block.start_address());
        }

        Ok(())
    }
}
