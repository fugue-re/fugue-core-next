use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fugue_sleigh_language::pattern::PatternExpression as SleighPatternExpression;
use fugue_sleigh_language::symbol::sub_table::DecisionNode as SleighDecisionNode;
use fugue_sleigh_language::symbol::Symbol as SleighSymbol;
use fugue_sleigh_language::{
    construct as sleigh_construct, Language as SleighLanguage, LanguageDB, LanguageError,
};
use indexmap::IndexMap;
use thiserror::Error;

use crate::context::ContextBitRange;
use crate::dynamic::blob;
use crate::operand::Operand;
use crate::pattern::PatternOp;
use crate::pcode::Varnode;
use crate::space::AddressSpaceKind;
use crate::template::{ConstTpl, HandleTpl, VarnodeTpl};

mod context;
mod pattern;
mod symbol;
mod template;

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
    LanguageDb {
        path: PathBuf,
        #[source]
        source: LanguageError,
    },
    #[error("missing compiled .sla for `{language}`: expected `{path}` (build it offline before invoking the dynamic loader)")]
    SleighSlaMissing { language: String, path: PathBuf },
}

pub fn build(
    specs: impl AsRef<Path>,
    language: impl AsRef<str>,
) -> Result<blob::language::Language, BuildError> {
    build_inner(specs.as_ref(), language.as_ref(), None)
}

pub fn build_with_sla(
    specs: impl AsRef<Path>,
    language: impl AsRef<str>,
    sla: impl AsRef<Path>,
) -> Result<blob::language::Language, BuildError> {
    build_inner(specs.as_ref(), language.as_ref(), Some(sla.as_ref()))
}

fn build_inner(
    specs: &Path,
    language_def: &str,
    sla_override: Option<&Path>,
) -> Result<blob::language::Language, BuildError> {
    let database =
        LanguageDB::from_directory_with(specs, true).map_err(|source| BuildError::LanguageDb {
            path: specs.to_path_buf(),
            source,
        })?;

    let definition = database
        .lookup_str(language_def)
        .ok()
        .flatten()
        .ok_or_else(|| BuildError::Language(language_def.to_owned()))?;

    let context_defaults = definition
        .language()
        .context_set()
        .map(|(name, value)| (Box::<str>::from(name), value))
        .collect::<Box<[(Box<str>, u32)]>>();

    let language = match sla_override {
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

    let mut tables = Tables::default();
    tables.assign_indices(&language);
    tables.build_symbols_and_subtables(&language);
    tables.collect_context_variables(&language);
    Ok(tables.assemble(&language, context_defaults))
}

#[derive(Default)]
pub(crate) struct Tables<'a> {
    pub(crate) ctors: Vec<blob::constructor::Constructor>,
    pub(crate) dtrees: Vec<blob::resolve::DecisionNode>,
    pub(crate) operand_filters: Vec<blob::operand::OperandFilter>,
    pub(crate) pattern_ops: Vec<PatternOp>,
    pub(crate) symbols: Vec<blob::symbol::Symbol>,

    pub(crate) const_tpls: IndexMap<&'a sleigh_construct::ConstTpl, ConstTpl>,
    pub(crate) construct_tpls:
        IndexMap<&'a sleigh_construct::ConstructTpl, blob::template::ConstructTpl>,
    pub(crate) handle_tpls: IndexMap<&'a sleigh_construct::HandleTpl, HandleTpl>,
    pub(crate) op_tpls: IndexMap<&'a sleigh_construct::OpTpl, blob::template::OpTpl>,
    pub(crate) varnode_tpls: IndexMap<&'a sleigh_construct::VarnodeTpl, VarnodeTpl>,

    pub(crate) ctor_id_mapping: BTreeMap<(usize, usize, usize), usize>,
    pub(crate) operand_filter_id_mapping: BTreeMap<usize, usize>,
    pub(crate) subtable_id_mapping: BTreeMap<(usize, usize), usize>,
    pub(crate) symbol_id_mapping: BTreeMap<usize, usize>,

    pub(crate) context_variables: Vec<(Box<str>, usize, usize)>,
}

impl<'a> Tables<'a> {
    fn assign_indices(&mut self, language: &'a SleighLanguage) {
        let symtab = language.symbol_table();
        let mut ctor_idx = 0usize;
        let mut operand_filter_idx = 0usize;
        let mut subtable_idx = 0usize;
        let mut symbol_idx = 0usize;

        for symbol in symtab.symbols().iter() {
            match symbol {
                SleighSymbol::Subtable {
                    id,
                    scope,
                    decision_tree,
                    constructors,
                    ..
                } => {
                    let number_of_children = decision_tree.count_children();
                    let offset = subtable_idx + number_of_children;
                    self.subtable_id_mapping.insert((*id, *scope), offset);
                    subtable_idx = offset + 1;

                    for cidx in 0..constructors.len() {
                        self.ctor_id_mapping.insert((*id, *scope, cidx), ctor_idx);
                        ctor_idx += 1;
                    }
                }
                SleighSymbol::UserOp { .. }
                | SleighSymbol::Context { .. }
                | SleighSymbol::FlowDest { .. }
                | SleighSymbol::FlowRef { .. } => {}
                _ => {
                    self.symbol_id_mapping.insert(symbol.id(), symbol_idx);
                    symbol_idx += 1;

                    if symbol.has_filter() {
                        self.operand_filter_id_mapping
                            .insert(symbol.id(), operand_filter_idx);
                        operand_filter_idx += 1;
                    }
                }
            }
        }
    }

    fn build_symbols_and_subtables(&mut self, language: &'a SleighLanguage) {
        for symbol in language.symbol_table().symbols().iter() {
            if let SleighSymbol::Subtable {
                id,
                scope,
                constructors,
                decision_tree,
                ..
            } = symbol
            {
                self.generate_subtable(language, *id, *scope, constructors, decision_tree);
                continue;
            }

            if matches!(
                symbol,
                SleighSymbol::UserOp { .. }
                    | SleighSymbol::Context { .. }
                    | SleighSymbol::FlowDest { .. }
                    | SleighSymbol::FlowRef { .. }
            ) {
                continue;
            }

            if let Some(converted) = symbol::convert_symbol(language, symbol, self) {
                self.symbols.push(converted);
            }
            if let Some(filter) = symbol::convert_operand_filter(language, symbol, self) {
                self.operand_filters.push(filter);
            }
        }
    }

    fn collect_context_variables(&mut self, language: &'a SleighLanguage) {
        let symtab = language.symbol_table();
        for &sym_id in symtab.global_scope().unwrap().iter() {
            let SleighSymbol::Context {
                name,
                pattern_value,
                ..
            } = symtab.symbol(sym_id).unwrap()
            else {
                continue;
            };

            if let SleighPatternExpression::ContextField {
                bit_start, bit_end, ..
            } = pattern_value
            {
                self.context_variables.push((
                    String::from(name.as_str()).into_boxed_str(),
                    *bit_start,
                    *bit_end,
                ));
            }
        }
    }

    fn assemble(
        self,
        language: &'a SleighLanguage,
        context_defaults: Box<[(Box<str>, u32)]>,
    ) -> blob::language::Language {
        let arch = language.architecture();
        let default_space = language.spaces().default_space_ref();
        let constant_space_id = language.spaces().constant_space_id().index() as u8;
        let default_space_id = default_space.index() as u8;
        let register_space_id = language.spaces().register_space_id().index() as u8;
        let unique_space_id = language.spaces().unique_space_id().index() as u8;

        let address_size = default_space.address_size();
        let address_bits = (address_size as u32) * 8;
        let address_upper_bound = default_space.highest_offset();

        let spaces = language
            .spaces()
            .iter()
            .map(|spc| blob::space::AddressSpace {
                name: spc.name().into(),
                word_size: spc.word_size(),
                upper_bound: spc.highest_offset(),
                kind: classify_space(spc, default_space_id),
            })
            .collect::<Box<[blob::space::AddressSpace]>>();

        let space_names = language
            .spaces()
            .iter()
            .map(|spc| String::from(spc.name()).into_boxed_str())
            .collect::<Box<[Box<str>]>>();

        let user_ops = language
            .user_ops()
            .iter()
            .map(|op| String::from(op.as_str()).into_boxed_str())
            .collect::<Box<[Box<str>]>>();

        let mut register_pairs = Vec::<(Box<str>, Varnode)>::new();
        let mut register_ranges = Vec::<(u64, u16, Box<str>)>::new();
        for ((off, sz), nm) in language.registers().iter() {
            let off = *off;
            let sz = *sz as u16;
            let nm = String::from(nm.as_str()).into_boxed_str();
            register_pairs.push((nm.clone(), Varnode::new(register_space_id, off, sz)));
            register_ranges.push((off, sz, nm));
        }
        register_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        register_ranges.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        let mut context_pairs = self
            .context_variables
            .iter()
            .map(|(name, start, end)| (name.clone(), ContextBitRange::new(*start, *end)))
            .collect::<Vec<(Box<str>, ContextBitRange)>>();
        context_pairs.sort_by(|a, b| a.0.cmp(&b.0));

        let root_dtree = u16::try_from(self.subtable_id_mapping[&(0, 0)])
            .expect("root decision tree id fits in u16");

        let const_templates = self.const_tpls.into_values().collect::<Box<[ConstTpl]>>();
        let construct_templates = self
            .construct_tpls
            .into_values()
            .collect::<Box<[blob::template::ConstructTpl]>>();
        let handle_templates = self.handle_tpls.into_values().collect::<Box<[HandleTpl]>>();
        let op_templates = self
            .op_tpls
            .into_values()
            .collect::<Box<[blob::template::OpTpl]>>();
        let varnode_templates = self
            .varnode_tpls
            .into_values()
            .collect::<Box<[VarnodeTpl]>>();

        blob::language::Language {
            id: arch.to_string().into(),
            processor: arch.processor().into(),
            variant: arch.variant().into(),
            little_endian: arch.endian().is_little(),
            address_alignment: language.alignment(),
            address_bits,
            address_size,
            address_upper_bound,
            constant_space: constant_space_id,
            default_space: default_space_id,
            register_space: register_space_id,
            register_space_size: language.register_space_size(),
            unique_mask: language.unique_mask(),
            unique_space: unique_space_id,
            unique_space_size: language.unique_space_size(),
            root_dtree,
            spaces,
            constructors: self.ctors.into_boxed_slice(),
            decision_trees: self.dtrees.into_boxed_slice(),
            operand_filters: self.operand_filters.into_boxed_slice(),
            pattern_expressions: self.pattern_ops.into_boxed_slice(),
            symbols: self.symbols.into_boxed_slice(),
            const_templates,
            construct_templates,
            handle_templates,
            op_templates,
            varnode_templates,
            registers: register_pairs.into_boxed_slice(),
            register_ranges: register_ranges.into_boxed_slice(),
            user_ops,
            context_vars: context_pairs.into_boxed_slice(),
            context_defaults,
            space_names,
        }
    }

    fn generate_subtable(
        &mut self,
        language: &'a SleighLanguage,
        id: usize,
        scope: usize,
        ctors: &'a [fugue_sleigh_language::symbol::sub_table::Constructor],
        dtree: &'a SleighDecisionNode,
    ) {
        for (cid, ctor) in ctors.iter().enumerate() {
            let mapped_id =
                u16::try_from(self.ctor_for(id, scope, cid)).expect("constructor id fits in u16");

            let print_pieces = ctor
                .print_pieces()
                .iter()
                .map(|piece| {
                    if piece.as_bytes().first() == Some(&b'\n') {
                        let index = u16::from(piece.as_bytes()[1] - b'A');
                        blob::constructor::PrintPiece::Operand(index)
                    } else {
                        blob::constructor::PrintPiece::Token(
                            String::from(piece.as_str()).into_boxed_str(),
                        )
                    }
                })
                .collect::<Box<[_]>>();

            let operands = self.build_operands(language, ctor);
            let (pre_actions, post_actions) = self.build_context_actions(language, ctor);
            let result = self.build_template_result(language, ctor);
            let build_action = self.build_template_action(language, ctor);

            self.ctors.push(blob::constructor::Constructor {
                id: mapped_id,
                context_pre_actions: pre_actions,
                context_post_actions: post_actions,
                operands,
                result,
                build_action,
                print_pieces,
                first_whitespace: ctor.first_whitespace(),
                flow_through_index: ctor.flow_through_index(),
                delay_slot_length: ctor
                    .template()
                    .map(|tpl| tpl.delay_slot())
                    .unwrap_or_default(),
                minimum_length: ctor.minimum_length(),
            });
        }

        self.flatten_decision_tree(id, scope, dtree);
    }

    fn build_operands(
        &mut self,
        language: &'a SleighLanguage,
        ctor: &'a fugue_sleigh_language::symbol::sub_table::Constructor,
    ) -> Box<[Operand]> {
        let mut operands = Vec::with_capacity(ctor.operand_count());

        for oid in 0..ctor.operand_count() {
            let operand_sym_id = ctor.operand(oid);
            let operand = language.symbol_table().symbol(operand_sym_id).unwrap();

            let offset_base = operand.offset_base();
            let offset_rela = operand.relative_offset();
            let minimum_length = if let SleighSymbol::Operand { min_length, .. } = operand {
                *min_length
            } else {
                unreachable!("operand has Operand kind")
            };

            let (resolver, handle_resolver) = symbol::operand_resolvers(language, operand, self);

            operands.push(Operand {
                resolver,
                handle_resolver,
                offset_base,
                offset_rela,
                minimum_length,
            });
        }

        operands.into_boxed_slice()
    }

    fn build_context_actions(
        &mut self,
        language: &'a SleighLanguage,
        ctor: &'a fugue_sleigh_language::symbol::sub_table::Constructor,
    ) -> (
        Box<[crate::context::ContextPreAction]>,
        Box<[crate::context::ContextPostAction]>,
    ) {
        let mut pre = Vec::new();
        let mut post = Vec::new();
        for action in ctor.context().iter() {
            match action {
                fugue_sleigh_language::symbol::sub_table::Context::Operator { .. } => {
                    pre.push(context::convert_pre_action(language, action, self));
                }
                fugue_sleigh_language::symbol::sub_table::Context::Commit { .. } => {
                    post.push(context::convert_post_action(language, action, self));
                }
            }
        }
        (pre.into_boxed_slice(), post.into_boxed_slice())
    }

    fn build_template_result(
        &mut self,
        language: &'a SleighLanguage,
        ctor: &'a fugue_sleigh_language::symbol::sub_table::Constructor,
    ) -> Option<u16> {
        ctor.template()
            .and_then(sleigh_construct::ConstructTpl::result)
            .map(|tmpl| template::handle_tpl_index(language, tmpl, self))
    }

    fn build_template_action(
        &mut self,
        language: &'a SleighLanguage,
        ctor: &'a fugue_sleigh_language::symbol::sub_table::Constructor,
    ) -> Option<u16> {
        ctor.template()
            .map(|tmpl| template::construct_tpl_index(language, tmpl, self))
    }

    fn flatten_decision_tree(
        &mut self,
        id: usize,
        scope: usize,
        dtree: &'a SleighDecisionNode,
    ) -> u16 {
        let patterns = dtree
            .patterns()
            .iter()
            .map(|pat| build_decision_pair(self, id, scope, pat))
            .collect::<Box<[_]>>();

        let mut children_ids = Vec::with_capacity(dtree.children().len());
        for child in dtree.children() {
            children_ids.push(self.flatten_decision_tree(id, scope, child));
        }

        let dtree_id = self.dtrees.len();
        self.dtrees.push(blob::resolve::DecisionNode {
            start_bit: dtree.start_bit() as u32,
            size: dtree.size() as u32,
            context_decision: dtree.context_decision(),
            patterns,
            children: children_ids.into_boxed_slice(),
        });

        u16::try_from(dtree_id).expect("decision tree id fits in u16")
    }

    pub(crate) fn ctor_for(&self, id: usize, scope: usize, ctor: usize) -> usize {
        self.ctor_id_mapping[&(id, scope, ctor)]
    }

    pub(crate) fn symbol_for(&self, sym_id: usize) -> u16 {
        u16::try_from(self.symbol_id_mapping[&sym_id]).expect("symbol id fits in u16")
    }

    pub(crate) fn extend_pattern_ops(
        &mut self,
        iter: impl ExactSizeIterator<Item = PatternOp>,
    ) -> (u16, u16) {
        let spos = self.pattern_ops.len();
        self.pattern_ops.extend(iter);
        let epos = self.pattern_ops.len();
        let spos = u16::try_from(spos).expect("pattern op start fits in u16");
        let epos = u16::try_from(epos).expect("pattern op end fits in u16");
        (spos, epos)
    }
}

fn classify_space(
    space: &fugue_sleigh_language::spaces::AddressSpace,
    default_space_id: u8,
) -> AddressSpaceKind {
    let id = space.id();
    if id.is_constant() {
        AddressSpaceKind::Constant
    } else if id.is_unique() {
        AddressSpaceKind::Unique
    } else if (space.index() as u8) == default_space_id {
        AddressSpaceKind::Default
    } else {
        AddressSpaceKind::Other
    }
}

fn build_pattern(
    pattern: &fugue_sleigh_language::symbol::sub_table::PatternBlock,
) -> blob::resolve::Pattern {
    blob::resolve::Pattern {
        offset: pattern.offset(),
        non_zero_size: pattern.non_zero_size(),
        masks: pattern.masks().to_vec().into_boxed_slice(),
        values: pattern.values().to_vec().into_boxed_slice(),
    }
}

fn build_decision_pair(
    tables: &Tables<'_>,
    id: usize,
    scope: usize,
    pat: &fugue_sleigh_language::symbol::sub_table::DecisionPair,
) -> blob::resolve::DecisionPair {
    let constructor =
        u16::try_from(tables.ctor_for(id, scope, pat.id())).expect("constructor id fits in u16");

    let pattern = match pat.pattern() {
        fugue_sleigh_language::symbol::sub_table::DisjointPattern::Instruction(p) => {
            blob::resolve::DisjointPattern::Instruction(build_pattern(p.mask_value()))
        }
        fugue_sleigh_language::symbol::sub_table::DisjointPattern::Context(p) => {
            blob::resolve::DisjointPattern::Context(build_pattern(p.mask_value()))
        }
        fugue_sleigh_language::symbol::sub_table::DisjointPattern::Combine {
            context,
            instruction,
        } => blob::resolve::DisjointPattern::Combine {
            context: build_pattern(context.mask_value()),
            instruction: build_pattern(instruction.mask_value()),
        },
    };

    blob::resolve::DecisionPair {
        pattern,
        constructor,
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use super::{build, BuildError};

    fn specs_for(arch: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(arch)
            .join("data/processors")
    }

    fn try_build(arch: &str, language: &str) {
        let result = build(specs_for(arch), language);
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
