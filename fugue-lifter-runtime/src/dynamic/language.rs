use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use fugue_sleigh_language::{Language as SleighLanguage, LanguageDB, LanguageError};
use rkyv::rancor::Error as RkyvError;
use thiserror::Error;

use crate::context::ContextBitRange;
use crate::dynamic::constructor::Constructor;
use crate::dynamic::install::Install;
use crate::dynamic::operand::OperandFilter;
use crate::dynamic::resolve::DecisionNode;
use crate::dynamic::space::AddressSpace;
use crate::dynamic::symbol::Symbol;
use crate::dynamic::tables::Tables;
use crate::dynamic::template::{ConstructTpl, OpTpl};
use crate::dynamic::LanguageLoadError;
use crate::pattern::PatternOp;
use crate::pcode::Varnode;
use crate::template::{ConstTpl, HandleTpl, VarnodeTpl};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cannot locate language `{0}` in language database")]
    Language(String),
    #[error("cannot build language `{language}`: {source}")]
    LanguageBuild {
        language: String,
        #[source]
        source: LanguageError,
    },
    #[error("cannot load language database from `{path}`: {source}")]
    LanguageDB {
        path: PathBuf,
        #[source]
        source: LanguageError,
    },
    #[error("missing compiled .sla for `{language}`: expected `{path}` (build it offline before invoking the dynamic loader)")]
    SleighSlaMissing { language: String, path: PathBuf },
}

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Language {
    pub(crate) id: Box<str>,
    pub(crate) processor: Box<str>,
    pub(crate) variant: Box<str>,
    pub(crate) little_endian: bool,

    pub(crate) address_alignment: usize,
    pub(crate) address_bits: u32,
    pub(crate) address_size: usize,
    pub(crate) address_upper_bound: u64,

    pub(crate) constant_space: u8,
    pub(crate) default_space: u8,
    pub(crate) register_space: u8,
    pub(crate) register_space_size: usize,

    pub(crate) unique_mask: u64,
    pub(crate) unique_space: u8,
    pub(crate) unique_space_size: usize,

    pub(crate) root_dtree: u16,

    pub(crate) spaces: Box<[AddressSpace]>,

    pub(crate) constructors: Box<[Constructor]>,
    pub(crate) decision_trees: Box<[DecisionNode]>,
    pub(crate) operand_filters: Box<[OperandFilter]>,
    pub(crate) pattern_expressions: Box<[PatternOp]>,
    pub(crate) symbols: Box<[Symbol]>,

    pub(crate) const_templates: Box<[ConstTpl]>,
    pub(crate) construct_templates: Box<[ConstructTpl]>,
    pub(crate) handle_templates: Box<[HandleTpl]>,
    pub(crate) op_templates: Box<[OpTpl]>,
    pub(crate) varnode_templates: Box<[VarnodeTpl]>,

    pub(crate) registers: Box<[(Box<str>, Varnode)]>,
    pub(crate) register_ranges: Box<[(u64, u16, Box<str>)]>,
    pub(crate) user_ops: Box<[Box<str>]>,
    pub(crate) context_vars: Box<[(Box<str>, ContextBitRange)]>,
    pub(crate) context_defaults: Box<[(Box<str>, u32)]>,
    pub(crate) space_names: Box<[Box<str>]>,
}

impl Language {
    pub fn build(specs: impl AsRef<Path>, id: impl AsRef<str>) -> Result<Self, BuildError> {
        Self::build_inner(specs.as_ref(), id.as_ref(), None)
    }

    pub fn build_with_sla(
        specs: impl AsRef<Path>,
        id: impl AsRef<str>,
        sla: impl AsRef<Path>,
    ) -> Result<Self, BuildError> {
        Self::build_inner(specs.as_ref(), id.as_ref(), Some(sla.as_ref()))
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, LanguageLoadError> {
        rkyv::from_bytes::<Self, RkyvError>(bytes.as_ref()).map_err(LanguageLoadError::Deserialise)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LanguageLoadError> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|source| LanguageLoadError::io("open", path.to_path_buf(), source))?;
        let mut reader = GzDecoder::new(BufReader::new(file));
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| LanguageLoadError::io("read", path.to_path_buf(), source))?;
        Self::from_bytes(bytes)
    }

    pub fn to_bytes(&self) -> Result<impl AsRef<[u8]>, RkyvError> {
        rkyv::to_bytes::<RkyvError>(self).map(|aligned| aligned.into_vec().into_boxed_slice())
    }

    pub fn install(self) -> &'static crate::language::Language {
        let Self {
            id,
            processor,
            variant,
            little_endian,
            address_alignment,
            address_bits,
            address_size,
            address_upper_bound,
            constant_space,
            default_space,
            register_space,
            register_space_size,
            unique_mask,
            unique_space,
            unique_space_size,
            root_dtree,
            spaces,
            constructors,
            decision_trees,
            operand_filters,
            pattern_expressions,
            symbols,
            const_templates,
            construct_templates,
            handle_templates,
            op_templates,
            varnode_templates,
            registers,
            register_ranges,
            user_ops,
            context_vars,
            context_defaults,
            space_names,
        } = self;

        let spaces = spaces.install();
        let space_word_sizes = spaces
            .iter()
            .map(|spc| spc.word_size())
            .collect::<Box<[usize]>>()
            .install();
        let space_upper_bounds = spaces
            .iter()
            .map(|spc| spc.upper_bound())
            .collect::<Box<[u64]>>()
            .install();

        let language_data = Box::leak(Box::new(crate::language::LanguageData {
            root_dtree,
            address_size,
            constant_space,
            default_space,
            unique_space,
            spaces,
            constructors: constructors.install(),
            decision_trees: decision_trees.install(),
            operand_filters: operand_filters.install(),
            pattern_expressions: pattern_expressions.install(),
            symbols: symbols.install(),
            const_templates: const_templates.install(),
            construct_templates: construct_templates.install(),
            handle_templates: handle_templates.install(),
            op_templates: op_templates.install(),
            varnode_templates: varnode_templates.install(),
        }));

        Box::leak(Box::new(crate::language::Language {
            id: id.install(),
            processor: processor.install(),
            little_endian,
            variant: variant.install(),
            address_alignment,
            address_bits,
            address_size,
            address_upper_bound,
            constant_space,
            default_space,
            register_space,
            register_space_size,
            unique_mask,
            unique_space,
            unique_space_size,
            space_word_sizes,
            space_upper_bounds,
            registers: registers.install(),
            register_ranges: register_ranges.install(),
            user_ops: user_ops.install(),
            space_names: space_names.install(),
            context_vars: context_vars.install(),
            context_defaults: context_defaults.install(),
            data: language_data,
        }))
    }

    pub(crate) fn from_sleigh(
        sleigh: &SleighLanguage,
        defaults: impl IntoIterator<Item = (impl Into<Box<str>>, u32)>,
    ) -> Self {
        let tables = Tables::new(sleigh);
        let context_defaults = defaults
            .into_iter()
            .map(|(name, value)| (name.into(), value))
            .collect();

        let arch = sleigh.architecture();
        let default_space = sleigh.spaces().default_space_ref();
        let constant_space_id = sleigh.spaces().constant_space_id().index() as u8;
        let default_space_id = default_space.index() as u8;
        let register_space_id = sleigh.spaces().register_space_id().index() as u8;
        let unique_space_id = sleigh.spaces().unique_space_id().index() as u8;

        let address_size = default_space.address_size();
        let address_bits = (address_size as u32) * 8;
        let address_upper_bound = default_space.highest_offset();

        let spaces = sleigh
            .spaces()
            .iter()
            .map(|spc| AddressSpace::from_sleigh(spc, default_space_id))
            .collect::<Box<[AddressSpace]>>();

        let space_names = sleigh
            .spaces()
            .iter()
            .map(|spc| Box::<str>::from(spc.name()))
            .collect::<Box<[Box<str>]>>();

        let user_ops = sleigh
            .user_ops()
            .iter()
            .map(|op| Box::<str>::from(op.as_str()))
            .collect::<Box<[Box<str>]>>();

        let mut register_pairs = Vec::<(Box<str>, Varnode)>::new();
        let mut register_ranges = Vec::<(u64, u16, Box<str>)>::new();
        for ((off, sz), nm) in sleigh.registers().iter() {
            let off = *off;
            let sz = *sz as u16;
            register_pairs.push((
                Box::<str>::from(nm.as_str()),
                Varnode::new(register_space_id, off, sz),
            ));
            register_ranges.push((off, sz, Box::<str>::from(nm.as_str())));
        }
        register_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        register_ranges.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        let root_dtree = tables.root_dtree_id();

        let Tables {
            ctors,
            dtrees,
            operand_filters,
            pattern_ops,
            symbols,
            const_tpls,
            construct_tpls,
            handle_tpls,
            op_tpls,
            varnode_tpls,
            context_variables,
            ..
        } = tables;

        let mut context_pairs = context_variables
            .into_iter()
            .map(|(name, start, end)| (name, ContextBitRange::new(start, end)))
            .collect::<Vec<(Box<str>, ContextBitRange)>>();
        context_pairs.sort_by(|a, b| a.0.cmp(&b.0));

        Self {
            id: arch.to_string().into_boxed_str(),
            processor: Box::<str>::from(arch.processor()),
            variant: Box::<str>::from(arch.variant()),
            little_endian: arch.endian().is_little(),
            address_alignment: sleigh.alignment(),
            address_bits,
            address_size,
            address_upper_bound,
            constant_space: constant_space_id,
            default_space: default_space_id,
            register_space: register_space_id,
            register_space_size: sleigh.register_space_size(),
            unique_mask: sleigh.unique_mask(),
            unique_space: unique_space_id,
            unique_space_size: sleigh.unique_space_size(),
            root_dtree,
            spaces,
            constructors: ctors.into_boxed_slice(),
            decision_trees: dtrees.into_boxed_slice(),
            operand_filters: operand_filters.into_boxed_slice(),
            pattern_expressions: pattern_ops.into_boxed_slice(),
            symbols: symbols.into_boxed_slice(),
            const_templates: const_tpls.into_values().collect(),
            construct_templates: construct_tpls.into_values().collect(),
            handle_templates: handle_tpls.into_values().collect(),
            op_templates: op_tpls.into_values().collect(),
            varnode_templates: varnode_tpls.into_values().collect(),
            registers: register_pairs.into_boxed_slice(),
            register_ranges: register_ranges.into_boxed_slice(),
            user_ops,
            context_vars: context_pairs.into_boxed_slice(),
            context_defaults,
            space_names,
        }
    }

    fn build_inner(
        specs: &Path,
        language_def: &str,
        sla_override: Option<&Path>,
    ) -> Result<Self, BuildError> {
        let database = LanguageDB::from_directory_with(specs, true).map_err(|source| {
            BuildError::LanguageDB {
                path: specs.to_path_buf(),
                source,
            }
        })?;

        let definition = database
            .lookup_str(language_def)
            .ok()
            .flatten()
            .ok_or_else(|| BuildError::Language(language_def.to_owned()))?;

        let sleigh = match sla_override {
            Some(path) => definition.build_with_sla(path),
            None => {
                let sla_file = definition.language().sla_file();
                if !sla_file.exists() {
                    return Err(BuildError::SleighSlaMissing {
                        language: language_def.to_owned(),
                        path: sla_file.to_path_buf(),
                    });
                }
                definition.build()
            }
        }
        .map_err(|source| BuildError::LanguageBuild {
            language: language_def.to_owned(),
            source,
        })?;

        Ok(Self::from_sleigh(
            &sleigh,
            definition.language().context_set(),
        ))
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use super::{BuildError, Language};

    fn specs_for(arch: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(arch)
            .join("data/processors")
    }

    fn try_build(arch: &str, language: &str) {
        let result = Language::build(specs_for(arch), language);
        match result {
            Ok(blob) => {
                assert!(!blob.constructors.is_empty());
                assert!(!blob.decision_trees.is_empty());
                assert!(!blob.symbols.is_empty());
                assert!(!blob.spaces.is_empty());
                assert!((blob.root_dtree as usize) < blob.decision_trees.len());
            }
            Err(BuildError::SleighSlaMissing { .. }) => {}
            Err(other) => panic!("unexpected build error for {language}: {other}"),
        }
    }

    #[test]
    fn builds_x86_64_blob() {
        try_build("fugue-lifter-x86", "x86:LE:64:default");
    }

    #[test]
    fn builds_x86_blob() {
        try_build("fugue-lifter-x86", "x86:LE:32:default");
    }

    #[test]
    fn builds_arm_le_blob() {
        try_build("fugue-lifter-arm", "ARM:LE:32:v8");
    }

    #[test]
    fn builds_arm_be_blob() {
        try_build("fugue-lifter-arm", "ARM:BE:32:v8");
    }

    #[test]
    fn builds_aarch64_le_blob() {
        try_build("fugue-lifter-aarch64", "AARCH64:LE:64:v8A");
    }

    #[test]
    fn builds_aarch64_be_blob() {
        try_build("fugue-lifter-aarch64", "AARCH64:BE:64:v8A");
    }
}
