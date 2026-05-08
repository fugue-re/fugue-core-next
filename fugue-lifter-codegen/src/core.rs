use std::collections::BTreeMap;

use fugue_sleigh_language::construct::{ConstTpl, ConstructTpl, HandleTpl, OpTpl, VarnodeTpl};
use fugue_sleigh_language::pattern::PatternExpression;
use fugue_sleigh_language::symbol::sub_table::{
    Context, DecisionPair, DisjointPattern, PatternBlock,
};
use fugue_sleigh_language::symbol::{Constructor, DecisionNode, Symbol};
use fugue_sleigh_language::Language;
use indexmap::IndexMap;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};

use crate::types::context::ContextAdaptor;
use crate::types::pattern::PatternExpressionAdaptor;
use crate::types::symbol::SymbolAdaptor;
use crate::types::template::TplAdaptor;
use crate::{LanguageVariant, LifterGeneratorError};

pub struct LifterGenerator<'a> {
    context_variables: Vec<(&'a str, usize, usize)>,
    language: &'a Language,
    tables: Tables<'a>,
    primary_variant: LanguageVariant,
    extra_variants: Vec<LanguageVariant>,
}

#[derive(Default)]
pub(crate) struct Tables<'a> {
    ctors: Vec<TokenStream>,
    dtrees: Vec<TokenStream>,
    operand_filters: Vec<TokenStream>,
    pattern_ops: Vec<TokenStream>,
    symbols: Vec<TokenStream>,

    // NOTE: we could attempt to dedup. these templates
    const_tpls: IndexMap<&'a ConstTpl, TokenStream>,
    construct_tpls: IndexMap<&'a ConstructTpl, TokenStream>,
    handle_tpls: IndexMap<&'a HandleTpl, TokenStream>,
    op_tpls: IndexMap<&'a OpTpl, TokenStream>,
    varnode_tpls: IndexMap<&'a VarnodeTpl, TokenStream>,

    ctor_id_mapping: BTreeMap<(usize, usize, usize), usize>, // (id, scope, ctor) -> ctor
    operand_filter_id_mapping: BTreeMap<usize, usize>,       // sym -> filter
    // FIXME: (id, scope) is not needed--id should be unique across scopes
    subtable_id_mapping: BTreeMap<(usize, usize), usize>, // (id, scope) -> dtree
    symbol_id_mapping: BTreeMap<usize, usize>,            // sym -> sym
}

impl<'a> Tables<'a> {
    pub(crate) fn ctor_for(&self, id: usize, scope: usize, ctor: usize) -> u16 {
        let key = (id, scope, ctor);
        u16::try_from(self.ctor_id_mapping[&key]).expect("constructor id fits in u16")
    }

    pub(crate) fn symbol_for(&self, sym_id: usize) -> u16 {
        u16::try_from(self.symbol_id_mapping[&sym_id]).expect("symbol id fits in u16")
    }

    pub(crate) fn extend_pattern_ops(
        &mut self,
        iter: impl ExactSizeIterator<Item = TokenStream>,
    ) -> (u16, u16) {
        let spos = self.pattern_ops.len();
        self.pattern_ops.extend(iter);
        let epos = self.pattern_ops.len();

        let spos = u16::try_from(spos).expect("spos fits in u16");
        let epos = u16::try_from(epos).expect("epos fits in u16");

        (spos, epos)
    }

    pub(crate) fn push_const_tpl(&mut self, v: &'a ConstTpl, tpl: TokenStream) -> u16 {
        let idx = if let Some(idx) = self.const_tpls.get_index_of(v) {
            idx
        } else {
            self.const_tpls.insert_full(v, tpl).0
        };
        u16::try_from(idx).expect("const tpl id fits in u16")
    }

    pub(crate) fn push_construct_tpl(&mut self, v: &'a ConstructTpl, tpl: TokenStream) -> u16 {
        let idx = if let Some(idx) = self.construct_tpls.get_index_of(v) {
            idx
        } else {
            self.construct_tpls.insert_full(v, tpl).0
        };
        u16::try_from(idx).expect("construct tpl id fits in u16")
    }

    pub(crate) fn push_handle_tpl(&mut self, v: &'a HandleTpl, tpl: TokenStream) -> u16 {
        let idx = if let Some(idx) = self.handle_tpls.get_index_of(v) {
            idx
        } else {
            self.handle_tpls.insert_full(v, tpl).0
        };
        u16::try_from(idx).expect("handle tpl id fits in u16")
    }

    pub(crate) fn push_op_tpl(&mut self, v: &'a OpTpl, tpl: TokenStream) -> u16 {
        let idx = if let Some(idx) = self.op_tpls.get_index_of(v) {
            idx
        } else {
            self.op_tpls.insert_full(v, tpl).0
        };
        u16::try_from(idx).expect("op tpl id fits in u16")
    }

    pub(crate) fn push_varnode_tpl(&mut self, v: &'a VarnodeTpl, tpl: TokenStream) -> u16 {
        let idx = if let Some(idx) = self.varnode_tpls.get_index_of(v) {
            idx
        } else {
            self.varnode_tpls.insert_full(v, tpl).0
        };
        u16::try_from(idx).expect("varnode tpl id fits in u16")
    }
}

impl<'a> LifterGenerator<'a> {
    pub fn new(
        language: &'a Language,
        variant: LanguageVariant,
    ) -> Result<Self, LifterGeneratorError> {
        Self::new_with(language, variant, std::iter::empty())
    }

    pub fn new_with(
        language: &'a Language,
        primary_variant: LanguageVariant,
        extra_variants: impl IntoIterator<Item = LanguageVariant>,
    ) -> Result<Self, LifterGeneratorError> {
        let mut slf = Self {
            context_variables: Vec::new(),
            language,
            tables: Tables::default(),
            primary_variant,
            extra_variants: extra_variants.into_iter().collect(),
        };

        slf.build()?;

        Ok(slf)
    }

    pub fn build(&mut self) -> Result<(), LifterGeneratorError> {
        let symtab = self.language.symbol_table();

        let mut ctor_idx = 0;
        let mut operand_filter_idx = 0;
        let mut subtable_idx = 0;
        let mut symbol_idx = 0;

        for symbol in symtab.symbols().iter() {
            match symbol {
                Symbol::Subtable {
                    id,
                    scope,
                    decision_tree,
                    constructors,
                    ..
                } => {
                    let number_of_children = decision_tree.count_children();
                    let offset = subtable_idx + number_of_children;

                    self.tables
                        .subtable_id_mapping
                        .insert((*id, *scope), offset);

                    subtable_idx = offset + 1;

                    for cidx in 0..constructors.len() {
                        let key = (*id, *scope, cidx);
                        self.tables.ctor_id_mapping.insert(key, ctor_idx);
                        ctor_idx += 1;
                    }
                }
                Symbol::UserOp { .. }
                | Symbol::Context { .. }
                | Symbol::FlowDest { .. }
                | Symbol::FlowRef { .. } => {
                    // no mapping
                }
                _ => {
                    self.tables
                        .symbol_id_mapping
                        .insert(symbol.id(), symbol_idx);
                    symbol_idx += 1;

                    if symbol.has_filter() {
                        self.tables
                            .operand_filter_id_mapping
                            .insert(symbol.id(), operand_filter_idx);
                        operand_filter_idx += 1;
                    }
                }
            }
        }

        for symbol in symtab.symbols().iter() {
            if let Symbol::Subtable {
                id,
                scope,
                constructors,
                decision_tree,
                ..
            } = symbol
            {
                self.generate_subtable(*id, *scope, constructors, decision_tree);
            } else {
                let mut resolver = SymbolAdaptor::new(&self.language, symbol, &mut self.tables);

                let symbol = resolver.symbol_tokens();
                let filter = resolver.operand_filter_tokens();

                if let Some(symbol) = symbol {
                    self.tables.symbols.push(symbol);
                }

                if let Some(filter) = filter {
                    self.tables.operand_filters.push(filter);
                }
            }
        }

        for &sym_id in symtab.global_scope().unwrap().iter() {
            let Symbol::Context {
                ref name,
                ref pattern_value,
                ..
            } = symtab.symbol(sym_id).unwrap()
            else {
                continue;
            };

            if let PatternExpression::ContextField {
                bit_start, bit_end, ..
            } = pattern_value
            {
                self.context_variables.push((name, *bit_start, *bit_end));
            }
        }

        Ok(())
    }

    fn generate_constructor_operand_resolvers(&mut self, ctor: &Constructor) -> Vec<TokenStream> {
        let mut operands = Vec::new();

        for oid in 0..ctor.operand_count() {
            let index = ctor.operand(oid);
            let operand = self.language.symbol_table().symbol(index).unwrap();

            let offset_base = operand
                .offset_base()
                .map(|v| quote! { Some(#v) })
                .unwrap_or(quote! { None });
            let offset_rela = operand.relative_offset();
            let minimum_length = if let Symbol::Operand { min_length, .. } = operand {
                min_length
            } else {
                unreachable!()
            };

            let (resolver, handle_resolver) = if let Some(tsym) =
                operand.defining_symbol(self.language.symbol_table())
            {
                match tsym {
                    Symbol::Subtable { id, scope, .. } => {
                        let dtree_id =
                            u16::try_from(self.tables.subtable_id_mapping[&(*id, *scope)])
                                .expect("decision tree id fits in u16");
                        let resolver = quote! { fugue_lifter_runtime::OperandResolver::Constructor(#dtree_id) };
                        let handle_resolver =
                            quote! { fugue_lifter_runtime::OperandHandleResolver::None };

                        (resolver, handle_resolver)
                    }
                    Symbol::ValueMap {
                        id,
                        table_is_filled,
                        ..
                    } => {
                        let resolver = if *table_is_filled {
                            quote! { fugue_lifter_runtime::OperandResolver::None }
                        } else {
                            let index = u16::try_from(self.tables.operand_filter_id_mapping[&id])
                                .expect("operand filter id fits in u16");
                            quote! { fugue_lifter_runtime::OperandResolver::Filter(#index) }
                        };

                        let index = u16::try_from(self.tables.symbol_id_mapping[&id])
                            .expect("symbol id fits in u16");
                        let handle_resolver =
                            quote! { fugue_lifter_runtime::OperandHandleResolver::Symbol(#index) };

                        (resolver, handle_resolver)
                    }
                    Symbol::VarnodeList {
                        id,
                        table_is_filled,
                        ..
                    } => {
                        let resolver = if *table_is_filled {
                            quote! { fugue_lifter_runtime::OperandResolver::None }
                        } else {
                            let index = u16::try_from(self.tables.operand_filter_id_mapping[&id])
                                .expect("operand filter id fits in u16");
                            quote! { fugue_lifter_runtime::OperandResolver::Filter(#index) }
                        };

                        let index = u16::try_from(self.tables.symbol_id_mapping[&id])
                            .expect("symbol id fits in u16");
                        let handle_resolver =
                            quote! { fugue_lifter_runtime::OperandHandleResolver::Symbol(#index) };

                        (resolver, handle_resolver)
                    }
                    Symbol::Name {
                        id,
                        table_is_filled,
                        ..
                    } => {
                        let resolver = if *table_is_filled {
                            quote! { fugue_lifter_runtime::OperandResolver::None }
                        } else {
                            let index = u16::try_from(self.tables.operand_filter_id_mapping[&id])
                                .expect("operand filter id fits in u16");
                            quote! { fugue_lifter_runtime::OperandResolver::Filter(#index) }
                        };

                        let index = u16::try_from(self.tables.symbol_id_mapping[&id])
                            .expect("symbol id fits in u16");
                        let handle_resolver =
                            quote! { fugue_lifter_runtime::OperandHandleResolver::Symbol(#index) };

                        (resolver, handle_resolver)
                    }
                    symbol => {
                        let resolver = quote! { fugue_lifter_runtime::OperandResolver::None };

                        let id = symbol.id();
                        let index = u16::try_from(self.tables.symbol_id_mapping[&id])
                            .expect("symbol id fits in u16");
                        let handle_resolver =
                            quote! { fugue_lifter_runtime::OperandHandleResolver::Symbol(#index) };

                        (resolver, handle_resolver)
                    }
                }
            } else {
                let resolver = quote! { fugue_lifter_runtime::OperandResolver::None };

                let pexp = operand.defining_expression().unwrap();
                let value = PatternExpressionAdaptor::new(&self.language, pexp, &mut self.tables)
                    .pattern_expression_tokens();
                let handle_resolver =
                    quote! { fugue_lifter_runtime::OperandHandleResolver::Expression(#value) };

                (resolver, handle_resolver)
            };

            operands.push(quote! {
                fugue_lifter_runtime::Operand {
                    resolver: #resolver,
                    handle_resolver: #handle_resolver,
                    offset_base: #offset_base,
                    offset_rela: #offset_rela,
                    minimum_length: #minimum_length,
                }
            });
        }

        operands
    }

    fn generate_constructor_context_actions(
        &mut self,
        ctor: &'a Constructor,
    ) -> (Vec<TokenStream>, Vec<TokenStream>) {
        let mut pre_actions = Vec::new();
        let mut post_actions = Vec::new();

        for action in ctor.context().iter() {
            match action {
                Context::Operator { .. } => {
                    pre_actions.push(
                        ContextAdaptor::new(&self.language, action, &mut self.tables)
                            .context_action_tokens(),
                    );
                }
                Context::Commit { .. } => {
                    post_actions.push(
                        ContextAdaptor::new(&self.language, action, &mut self.tables)
                            .context_action_tokens(),
                    );
                }
            }
        }

        (pre_actions, post_actions)
    }

    fn generate_handle_template(&mut self, tmpl: &'a HandleTpl) -> u16 {
        TplAdaptor::new(&self.language, tmpl, &mut self.tables).tokens()
    }

    fn generate_constructor_template_resolvers(&mut self, ctor: &'a Constructor) -> TokenStream {
        if let Some(templ) = ctor.template().and_then(ConstructTpl::result) {
            let action = self.generate_handle_template(templ);
            quote! {
                Some(#action)
            }
        } else {
            quote! { None }
        }
    }

    fn generate_constructor_build_action(&mut self, tmpl: &'a ConstructTpl) -> u16 {
        TplAdaptor::new(&self.language, tmpl, &mut self.tables).tokens()
    }

    fn generate_constructor_lifting_actions(&mut self, ctor: &'a Constructor) -> TokenStream {
        if let Some(tmpl) = ctor.template() {
            let template = self.generate_constructor_build_action(tmpl);
            quote! { Some(#template) }
        } else {
            quote! { None }
        }
    }

    fn generate_constructors(&mut self, id: usize, scope: usize, ctors: &'a [Constructor]) {
        ctors.iter().enumerate().for_each(move |(cid, ctor)| {
            /*
            let (ctor_id1, ctor_id2) = ctor.id();
            let ctor_id = (ctor_id1 as u32 & 0xffff) << 16 | (ctor_id2 as u32 & 0xffff);
            */

            let delay_slot_length = ctor
                .template()
                .map(|tpl| tpl.delay_slot())
                .unwrap_or_default();
            let minimum_length = ctor.minimum_length();

            let pieces = ctor.print_pieces().iter().map(|piece| {
                if piece.as_bytes()[0] == b'\n' {
                    let index = u16::try_from(piece.as_bytes()[1] - b'A')
                        .expect("operand index fits in u16");
                    quote! { fugue_lifter_runtime::constructor::PrintPiece::Operand(#index) }
                } else {
                    quote! { fugue_lifter_runtime::constructor::PrintPiece::Token(#piece) }
                }
            });

            let first_whitespace = ctor
                .first_whitespace()
                .map_or_else(|| quote! { None }, |index| quote! { Some(#index) });

            let flow_through_index = ctor
                .flow_through_index()
                .map_or_else(|| quote! { None }, |index| quote! { Some(#index) });

            let operands = self.generate_constructor_operand_resolvers(ctor);
            let (pre_actions, post_actions) = self.generate_constructor_context_actions(ctor);

            let template_result = self.generate_constructor_template_resolvers(ctor);
            let lifting_action = self.generate_constructor_lifting_actions(ctor);

            let cid = self.tables.ctor_for(id, scope, cid);

            self.tables.ctors.push(quote! {
                fugue_lifter_runtime::Constructor {
                    id: #cid,
                    context_pre_actions: &[#(#pre_actions),*],
                    context_post_actions: &[#(#post_actions),*],
                    operands: &[#(#operands),*],
                    result: #template_result,
                    build_action: #lifting_action,
                    print_pieces: &[#(#pieces),*],
                    first_whitespace: #first_whitespace,
                    flow_through_index: #flow_through_index,
                    delay_slot_length: #delay_slot_length,
                    minimum_length: #minimum_length,
                }
            });
        })
    }

    /*
    pub(crate) fn ctor_vname(id: usize, scope: usize, cid: usize) -> Ident {
        format_ident!("__SYM{id}_IN{scope}_CTOR{cid}")
    }

    fn generate_dtree_pmatch_ctxt(&self, cpat: &ContextPattern) -> TokenStream {
        let pat = cpat.mask_value();

        if pat.always_true() {
            return quote! { true };
        }

        if pat.always_false() {
            return quote! { false };
        }

        let parts = pat
            .masks()
            .iter()
            .zip(pat.values().iter())
            .enumerate()
            .map(|(i, (m, v))| {
                let size = size_of::<u32>();
                let offset = pat.offset() + i * size;

                quote! {
                    (input.inputs.input.context_bytes(#offset, #size) & #m == #v)
                }
            });

        quote! {
            (true #( && #parts )*)
        }
    }

    fn generate_dtree_pmatch_insn(&self, ipat: &InstructionPattern) -> TokenStream {
        let pat = ipat.mask_value();

        if pat.always_true() {
            return quote! { true };
        }

        if pat.always_false() {
            return quote! { false };
        }

        let parts = pat
            .masks()
            .iter()
            .zip(pat.values().iter())
            .enumerate()
            .map(|(i, (m, v))| {
                let size = size_of::<u32>();
                let offset = pat.offset() + i * size;

                quote! {
                    (input.inputs.input.instruction_bytes(#offset, #size)? & #m == #v)
                }
            });

        quote! {
            (true #( && #parts )*)
        }
    }

    fn generate_dtree_pmatch(&self, id: usize, scope: usize, pat: &DecisionPair) -> TokenStream {
        match pat.pattern() {
            DisjointPattern::Instruction(ipat) => {
                let cid = pat.id();
                let ctor = Self::ctor_vname(id, scope, cid);
                let cond = self.generate_dtree_pmatch_insn(ipat);

                quote! {
                    if #cond {
                        return Some(& #ctor);
                    }
                }
            }
            DisjointPattern::Context(cpat) => {
                let cid = pat.id();
                let ctor = Self::ctor_vname(id, scope, cid);
                let cond = self.generate_dtree_pmatch_ctxt(cpat);

                quote! {
                    if #cond {
                        return Some(& #ctor);
                    }
                }
            }
            DisjointPattern::Combine {
                context: cpat,
                instruction: ipat,
            } => {
                let cid = pat.id();
                let ctor = Self::ctor_vname(id, scope, cid);

                let ccond = self.generate_dtree_pmatch_ctxt(cpat);
                let icond = self.generate_dtree_pmatch_insn(ipat);

                quote! {
                    if #icond && #ccond {
                        return Some(& #ctor);
                    }
                }
            }
        }
    }

    fn generate_dtree_aux(
        &self,
        id: usize,
        scope: usize,
        dtree: &DecisionNode,
        tree_fn_prefix: &Ident,
        trees: &mut Vec<TokenStream>,
    ) -> TokenStream {
        if dtree.size() == 0 {
            // This is a leaf
            let parts = dtree
                .patterns()
                .iter()
                .map(|pat| self.generate_dtree_pmatch(id, scope, pat));

            quote! {
                #(#parts)*
                return None;
            }
        } else {
            // This is a node--generate a function call for each body
            let parts = dtree
                .children()
                .iter()
                .enumerate()
                .map(|(i, node)| {
                    let bitn = i as u32;
                    let tree_fn = format_ident!("{tree_fn_prefix}_{bitn}");
                    let body = self.generate_dtree_aux(id, scope, node, &tree_fn, trees);

                    trees.push(quote! {
                        #[inline]
                        fn #tree_fn(input: &mut fugue_lifter_runtime::LiftingContextState) -> Option<&'static fugue_lifter_runtime::Constructor> {
                            unsafe {
                                #body
                            }
                        }
                    });

                    quote! {
                        (#tree_fn as fn(&mut fugue_lifter_runtime::LiftingContextState) -> Option<&'static fugue_lifter_runtime::Constructor>)
                    }
                })
                .collect::<Vec<_>>();

            let start_bit = dtree.start_bit();
            let size = dtree.size();

            let check = if dtree.context_decision() {
                quote! { input.inputs.input.context_bits(#start_bit, #size) }
            } else {
                quote! { input.inputs.input.instruction_bits(#start_bit, #size)? }
            };

            let nodes = dtree.children().len();

            let table = Ident::new(
                &format!("{tree_fn_prefix}_LOOKUP").to_uppercase(),
                proc_macro2::Span::call_site(),
            );

            trees.push(quote! {
                const #table: [fn(&mut fugue_lifter_runtime::LiftingContextState) -> Option<&'static fugue_lifter_runtime::Constructor>; #nodes] = [
                    #(#parts),*
                ];
            });

            quote! {
                (#table.get(#check as usize)?)(input)
            }
        }
    }

    fn generate_dtree(
        &self,
        id: usize,
        scope: usize,
        dtree: &DecisionNode,
        trees: &mut Vec<TokenStream>,
    ) -> TokenStream {
        // This will give us the body for a resolver; we should also allow to process sub-ctors
        let tree_fn = format_ident!("resolve_{id}_in_{scope}");
        let body = self.generate_dtree_aux(id, scope, dtree, &tree_fn, trees);
        quote! {
            #[inline]
            pub fn resolve(input: &mut fugue_lifter_runtime::LiftingContextState) -> Option<&'static fugue_lifter_runtime::Constructor> {
                unsafe {
                    #body
                }
            }
        }
    }
    */

    fn generate_dtree_pattern(&self, pattern: &PatternBlock) -> TokenStream {
        let non_zero_size = pattern
            .non_zero_size()
            .map(|s| quote! { Some(#s) })
            .unwrap_or(quote! { None });
        let masks = pattern.masks().iter().map(|m| quote! { #m });
        let values = pattern.values().iter().map(|v| quote! { #v });
        let offset = pattern.offset();

        quote! {
            fugue_lifter_runtime::resolve::Pattern {
                offset: #offset,
                non_zero_size: #non_zero_size,
                masks: &[#(#masks),*],
                values: &[#(#values),*],
            }
        }
    }

    fn generate_dtree_decision(&self, id: usize, scope: usize, pat: &DecisionPair) -> TokenStream {
        let ctor = self.tables.ctor_for(id, scope, pat.id());

        let pattern = match pat.pattern() {
            DisjointPattern::Instruction(pat) => {
                let pat = self.generate_dtree_pattern(pat.mask_value());
                quote! {
                    fugue_lifter_runtime::resolve::DisjointPattern::Instruction(#pat)
                }
            }
            DisjointPattern::Context(pat) => {
                let pat = self.generate_dtree_pattern(pat.mask_value());
                quote! {
                    fugue_lifter_runtime::resolve::DisjointPattern::Context(#pat)
                }
            }
            DisjointPattern::Combine {
                context,
                instruction,
            } => {
                let context = self.generate_dtree_pattern(context.mask_value());
                let instruction = self.generate_dtree_pattern(instruction.mask_value());

                quote! {
                    fugue_lifter_runtime::resolve::DisjointPattern::Combine {
                        context: #context,
                        instruction: #instruction,
                    }
                }
            }
        };

        quote! {
            fugue_lifter_runtime::resolve::DecisionPair {
                pattern: #pattern,
                constructor: #ctor,
            }
        }
    }

    fn generate_dtree_simplified(&mut self, id: usize, scope: usize, dtree: &DecisionNode) -> u16 {
        let mut patterns = Vec::new();
        for pattern in dtree.patterns() {
            patterns.push(self.generate_dtree_decision(id, scope, pattern));
        }

        let mut children = Vec::new();
        for child in dtree.children() {
            children.push(self.generate_dtree_simplified(id, scope, child));
        }

        let start_bit = dtree.start_bit() as u32;
        let size = dtree.size() as u32;
        let context_decision = dtree.context_decision();

        let dtree_id = self.tables.dtrees.len();

        self.tables.dtrees.push(quote! {
            fugue_lifter_runtime::resolve::DecisionNode {
                start_bit: #start_bit,
                size: #size,
                context_decision: #context_decision,
                patterns: &[#(#patterns),*],
                children: &[#(#children),*],
            }
        });

        u16::try_from(dtree_id).expect("decision tree id fits in u16")
    }

    fn generate_subtable(
        &mut self,
        id: usize,
        scope: usize,
        ctors: &'a [Constructor],
        dtree: &DecisionNode,
    ) {
        // NOTE: constructors must be generated before decision trees, since dtrees refer to
        // constructors...
        self.generate_constructors(id, scope, ctors);
        self.generate_dtree_simplified(id, scope, dtree);
    }
}

impl<'a> ToTokens for LifterGenerator<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let alignment = self.language.alignment();
        let unique_mask = self.language.unique_mask();

        let default_space = self.language.spaces().default_space_ref();

        let constant_space_id = self.language.spaces().constant_space_id().index() as u8;
        let default_space_id = default_space.index() as u8;
        let register_space_id = self.language.spaces().register_space_id().index() as u8;
        let unique_space_id = self.language.spaces().unique_space_id().index() as u8;

        let address_size = default_space.address_size();
        let address_bits = address_size as u32 * 8;
        let max_address = default_space.highest_offset();

        let register_space_size = self.language.register_space_size();
        let unique_space_size = self.language.unique_space_size();

        let mut userops = Vec::new();
        let mut userop_to_names = Vec::new();

        for (i, op) in self.language.user_ops().iter().enumerate() {
            let id = i as u16;
            let name = op.as_str();

            let upper_snake_name = Ident::new(
                &heck::AsShoutySnakeCase(name).to_string(),
                Span::call_site(),
            );

            userops.push(quote! {
                pub const #upper_snake_name: u16 = #id;
            });
            userop_to_names.push(name);
        }

        let n_userops = self.language.user_ops().len();

        let space_word_sizes = self.language.spaces().iter().map(|spc| spc.word_size());

        let space_upper_bounds = self
            .language
            .spaces()
            .iter()
            .map(|spc| spc.highest_offset());

        let n_spaces = self.language.spaces().len();

        let space_kinds = self.language.spaces().iter().enumerate().map(|(i, spc)| {
            let id = spc.id();
            if id.is_constant() {
                quote! { fugue_lifter_runtime::space::AddressSpaceKind::Constant }
            } else if id.is_unique() {
                quote! { fugue_lifter_runtime::space::AddressSpaceKind::Unique }
            } else if (i as u8) == default_space_id {
                quote! { fugue_lifter_runtime::space::AddressSpaceKind::Default }
            } else {
                quote! { fugue_lifter_runtime::space::AddressSpaceKind::Other }
            }
        });

        let spaces = self
            .language
            .spaces()
            .iter()
            .zip(space_kinds)
            .map(|(spc, kind)| {
                let name = spc.name();
                let word_size = spc.word_size();
                let upper_bound = spc.highest_offset();
                quote! {
                    fugue_lifter_runtime::space::AddressSpace::new(
                        #name,
                        #word_size,
                        #upper_bound,
                        #kind,
                    )
                }
            });

        let space_names = self.language.spaces().iter().map(|spc| {
            let name = spc.name();
            quote! { #name }
        });

        let context_variable_consts = self.context_variables.iter().map(|(name, start, end)| {
            let upper_snake_name = Ident::new(
                &heck::AsShoutySnakeCase(*name).to_string(),
                Span::call_site(),
            );
            quote! {
                pub const #upper_snake_name: fugue_lifter_runtime::context::ContextBitRange =
                    fugue_lifter_runtime::context::ContextBitRange::new(#start, #end);
            }
        });

        let mut context_variable_pairs_sorted = self.context_variables.iter().collect::<Vec<_>>();
        context_variable_pairs_sorted.sort_by_key(|(name, _, _)| *name);
        let context_variable_pairs = context_variable_pairs_sorted.iter().map(|(name, _, _)| {
            let upper_snake_name = Ident::new(
                &heck::AsShoutySnakeCase(*name).to_string(),
                Span::call_site(),
            );
            quote! {
                (#name, #upper_snake_name)
            }
        });
        let n_context_vars = self.context_variables.len();

        let context_variable_registrations =
            self.context_variables.iter().map(|(name, start, end)| {
                quote! {
                    context.register_variable(#name, #start, #end);
                }
            });

        let n_registers = self.language.registers().name_mapping().len();

        let mut registers = Vec::with_capacity(n_registers);
        let mut register_ranges = Vec::with_capacity(n_registers);
        let mut register_pairs_unsorted =
            Vec::<(&str, u64, u16, Ident)>::with_capacity(n_registers);

        for ((off, sz), nm) in self.language.registers().iter() {
            let off = *off;
            let sz = *sz as u16;

            let upper_snake_name = Ident::new(
                &heck::AsShoutySnakeCase(nm.as_str()).to_string(),
                Span::call_site(),
            );

            let var = quote! {
                pub const #upper_snake_name: fugue_lifter_runtime::pcode::Varnode =
                    fugue_lifter_runtime::pcode::Varnode::new(#register_space_id, #off, #sz);
            };

            let nm = nm.as_str();

            let range_to_name = quote! {
                (#off, #sz, #nm)
            };

            registers.push(var);
            register_ranges.push(range_to_name);
            register_pairs_unsorted.push((nm, off, sz, upper_snake_name));
        }

        register_pairs_unsorted.sort_by_key(|(nm, _, _, _)| *nm);
        let register_pairs = register_pairs_unsorted.iter().map(|(nm, _, _, ident)| {
            quote! {
                (#nm, #ident)
            }
        });

        let language_id = self.language.architecture().to_string();
        let processor = self.language.architecture().processor();
        let little_endian = self.language.architecture().endian().is_little();

        let constructors = &self.tables.ctors;
        let root_dtree = u16::try_from(self.tables.subtable_id_mapping[&(0, 0)])
            .expect("root decision tree id fits in u16");
        let dtrees = &self.tables.dtrees;
        let operand_filters = &self.tables.operand_filters;
        let pattern_ops = &self.tables.pattern_ops;
        let symbols = &self.tables.symbols;

        let const_tpls = self.tables.const_tpls.values();
        let construct_tpls = self.tables.construct_tpls.values();
        let handle_tpls = self.tables.handle_tpls.values();
        let op_tpls = self.tables.op_tpls.values();
        let varnode_tpls = self.tables.varnode_tpls.values();

        let arch = self.language.architecture();
        let endian_label = if arch.endian().is_big() { "BE" } else { "LE" };
        let arch_processor = arch.processor().to_owned();
        let arch_bits = arch.bits();

        let variant_blocks = if self.extra_variants.is_empty() {
            let primary = &self.primary_variant;
            let defaults_lit = primary
                .context_defaults
                .iter()
                .map(|(name, value)| quote! { (#name, #value) });
            let n_defaults = primary.context_defaults.len();
            let primary_variant_str = primary.name.clone();
            vec![quote! {
                static CONTEXT_DEFAULTS: [(&'static str, u32); #n_defaults] = [
                    #(#defaults_lit),*
                ];

                struct L;
                impl fugue_lifter_runtime::language::LanguageImpl for L {
                    const ID: &'static str = LANGUAGE_ID;

                    const PROCESSOR: &'static str = #processor;
                    const LITTLE_ENDIAN: bool = #little_endian;
                    const VARIANT: &'static str = #primary_variant_str;

                    const ADDRESS_ALIGNMENT: usize = ADDRESS_ALIGNMENT;
                    const ADDRESS_BITS: u32 = ADDRESS_BITS;
                    const ADDRESS_SIZE: usize = ADDRESS_SIZE;
                    const ADDRESS_UPPER_BOUND: u64 = ADDRESS_UPPER_BOUND;

                    const CONSTANT_SPACE: u8 = CONSTANT_SPACE;
                    const DEFAULT_SPACE: u8 = DEFAULT_SPACE;

                    const REGISTER_SPACE: u8 = REGISTER_SPACE;
                    const REGISTER_SPACE_SIZE: usize = REGISTER_SPACE_SIZE;

                    const UNIQUE_MASK: u64 = UNIQUE_MASK;
                    const UNIQUE_SPACE: u8 = UNIQUE_SPACE;
                    const UNIQUE_SPACE_SIZE: usize = UNIQUE_SPACE_SIZE;

                    const SPACE_WORD_SIZES: &'static [usize] = &SPACE_WORD_SIZE;
                    const SPACE_UPPER_BOUNDS: &'static [u64] = &SPACE_UPPER_BOUND;

                    const REGISTERS: &'static [(&'static str, fugue_lifter_runtime::pcode::Varnode)] = &register::REGISTERS_BY_NAME;
                    const REGISTER_RANGES: &'static [(u64, u16, &'static str)] = &register::REGISTERS;
                    const USER_OPS: &'static [&'static str] = &user_op::USER_OPS;
                    const SPACE_NAMES: &'static [&'static str] = &space::SPACES;
                    const CONTEXT_VARS: &'static [(&'static str, fugue_lifter_runtime::context::ContextBitRange)] = &context::CONTEXT_VARIABLES;
                    const CONTEXT_DEFAULTS: &'static [(&'static str, u32)] = &CONTEXT_DEFAULTS;

                    const DATA: &'static fugue_lifter_runtime::language::LanguageData = &LANGUAGE_DATA;
                }
                pub static LANGUAGE: fugue_lifter_runtime::language::Language =
                    fugue_lifter_runtime::language::Language::new::<L>();
            }]
        } else {
            let mut blocks = Vec::with_capacity(1 + self.extra_variants.len());
            for variant in std::iter::once(&self.primary_variant).chain(self.extra_variants.iter())
            {
                let variant_name = variant.name.clone();
                let upper = variant_name.to_ascii_uppercase();
                let defaults_static =
                    Ident::new(&format!("{upper}_CONTEXT_DEFAULTS"), Span::call_site());
                let language_static = Ident::new(&format!("LANGUAGE_{upper}"), Span::call_site());
                let marker_struct = Ident::new(&format!("L{upper}"), Span::call_site());
                let language_id_lit = format!(
                    "{}:{}:{}:{}",
                    arch_processor, endian_label, arch_bits, variant_name
                );
                let defaults_lit = variant
                    .context_defaults
                    .iter()
                    .map(|(name, value)| quote! { (#name, #value) });
                let n_defaults = variant.context_defaults.len();
                blocks.push(quote! {
                    static #defaults_static: [(&'static str, u32); #n_defaults] = [
                        #(#defaults_lit),*
                    ];

                    struct #marker_struct;
                    impl fugue_lifter_runtime::language::LanguageImpl for #marker_struct {
                        const ID: &'static str = #language_id_lit;

                        const PROCESSOR: &'static str = #processor;
                        const LITTLE_ENDIAN: bool = #little_endian;
                        const VARIANT: &'static str = #variant_name;

                        const ADDRESS_ALIGNMENT: usize = ADDRESS_ALIGNMENT;
                        const ADDRESS_BITS: u32 = ADDRESS_BITS;
                        const ADDRESS_SIZE: usize = ADDRESS_SIZE;
                        const ADDRESS_UPPER_BOUND: u64 = ADDRESS_UPPER_BOUND;

                        const CONSTANT_SPACE: u8 = CONSTANT_SPACE;
                        const DEFAULT_SPACE: u8 = DEFAULT_SPACE;

                        const REGISTER_SPACE: u8 = REGISTER_SPACE;
                        const REGISTER_SPACE_SIZE: usize = REGISTER_SPACE_SIZE;

                        const UNIQUE_MASK: u64 = UNIQUE_MASK;
                        const UNIQUE_SPACE: u8 = UNIQUE_SPACE;
                        const UNIQUE_SPACE_SIZE: usize = UNIQUE_SPACE_SIZE;

                        const SPACE_WORD_SIZES: &'static [usize] = &SPACE_WORD_SIZE;
                        const SPACE_UPPER_BOUNDS: &'static [u64] = &SPACE_UPPER_BOUND;

                        const REGISTERS: &'static [(&'static str, fugue_lifter_runtime::pcode::Varnode)] = &register::REGISTERS_BY_NAME;
                        const REGISTER_RANGES: &'static [(u64, u16, &'static str)] = &register::REGISTERS;
                        const USER_OPS: &'static [&'static str] = &user_op::USER_OPS;
                        const SPACE_NAMES: &'static [&'static str] = &space::SPACES;
                        const CONTEXT_VARS: &'static [(&'static str, fugue_lifter_runtime::context::ContextBitRange)] = &context::CONTEXT_VARIABLES;
                        const CONTEXT_DEFAULTS: &'static [(&'static str, u32)] = &#defaults_static;

                        const DATA: &'static fugue_lifter_runtime::language::LanguageData = &LANGUAGE_DATA;
                    }
                    pub static #language_static: fugue_lifter_runtime::language::Language =
                        fugue_lifter_runtime::language::Language::new::<#marker_struct>();
                });
            }
            blocks
        };

        tokens.append_all(quote! {
            pub const LANGUAGE_ID: &'static str = #language_id;

            pub const ADDRESS_ALIGNMENT: usize = #alignment;
            pub const ADDRESS_BITS: u32 = #address_bits;
            pub const ADDRESS_SIZE: usize = #address_size;

            pub const ADDRESS_UPPER_BOUND: u64 = #max_address;

            pub const CONSTANT_SPACE: u8 = #constant_space_id;
            pub const DEFAULT_SPACE: u8 = #default_space_id;

            pub const REGISTER_SPACE: u8 = #register_space_id;
            pub const REGISTER_SPACE_SIZE: usize = #register_space_size;

            pub const UNIQUE_MASK: u64 = #unique_mask;
            pub const UNIQUE_SPACE: u8 = #unique_space_id;
            pub const UNIQUE_SPACE_SIZE: usize = #unique_space_size;

            pub const SPACE_WORD_SIZE: [usize; #n_spaces] = [
                #(#space_word_sizes),*
            ];
            pub const SPACE_UPPER_BOUND: [u64; #n_spaces] = [
                #(#space_upper_bounds),*
            ];

            pub mod context {
                #(#context_variable_consts)*

                pub const CONTEXT_VARIABLES: [(&'static str, fugue_lifter_runtime::context::ContextBitRange); #n_context_vars] = [
                    #(#context_variable_pairs,)*
                ];
            }

            pub mod space {
                pub const SPACES: [&'static str; #n_spaces] = [
                    #(#space_names,)*
                ];
            }

            pub mod register {
                #(#registers)*

                pub const REGISTERS: [(u64, u16, &'static str); #n_registers] = [
                    #(#register_ranges),*
                ];

                pub const REGISTERS_BY_NAME: [(&'static str, fugue_lifter_runtime::pcode::Varnode); #n_registers] = [
                    #(#register_pairs),*
                ];
            }

            pub mod user_op {
                #(#userops)*

                pub const USER_OPS: [&'static str; #n_userops] = [
                    #(#userop_to_names),*
                ];
            }

            static CONSTRUCTORS: &[fugue_lifter_runtime::Constructor] = &[
                #(#constructors,)*
            ];

            static DECISION_TREES: &[fugue_lifter_runtime::resolve::DecisionNode] = &[
                #(#dtrees,)*
            ];

            static OPERAND_FILTERS: &[fugue_lifter_runtime::operand::OperandFilter] = &[
                #(#operand_filters,)*
            ];

            static PATTERN_EXPRESSIONS: &[fugue_lifter_runtime::pattern::PatternOp] = &[
                #(#pattern_ops,)*
            ];

            static SYMBOLS: &[fugue_lifter_runtime::symbol::Symbol] = &[
                #(#symbols,)*
            ];

            static CONST_TEMPLATES: &[fugue_lifter_runtime::template::ConstTpl] = &[
                #(#const_tpls,)*
            ];

            static CONSTRUCT_TEMPLATES: &[fugue_lifter_runtime::template::ConstructTpl] = &[
                #(#construct_tpls,)*
            ];

            static HANDLE_TEMPLATES: &[fugue_lifter_runtime::template::HandleTpl] = &[
                #(#handle_tpls,)*
            ];

            static OP_TEMPLATES: &[fugue_lifter_runtime::template::OpTpl] = &[
                #(#op_tpls,)*
            ];

            static VARNODE_TEMPLATES: &[fugue_lifter_runtime::template::VarnodeTpl] = &[
                #(#varnode_tpls,)*
            ];

            static SPACES: [fugue_lifter_runtime::space::AddressSpace; #n_spaces] = [
                #(#spaces,)*
            ];

            pub static LANGUAGE_DATA: fugue_lifter_runtime::language::LanguageData =
                fugue_lifter_runtime::language::LanguageData {
                    root_dtree: #root_dtree,
                    address_size: ADDRESS_SIZE,
                    constant_space: CONSTANT_SPACE,
                    default_space: DEFAULT_SPACE,
                    unique_space: UNIQUE_SPACE,
                    constructors: CONSTRUCTORS,
                    decision_trees: DECISION_TREES,
                    operand_filters: OPERAND_FILTERS,
                    pattern_expressions: PATTERN_EXPRESSIONS,
                    spaces: &SPACES,
                    symbols: SYMBOLS,
                    const_templates: CONST_TEMPLATES,
                    construct_templates: CONSTRUCT_TEMPLATES,
                    handle_templates: HANDLE_TEMPLATES,
                    op_templates: OP_TEMPLATES,
                    varnode_templates: VARNODE_TEMPLATES,
                };

            #[inline]
            pub fn lifter_with(
                language: &'static fugue_lifter_runtime::language::Language,
                ninputs: usize,
                context: fugue_lifter_runtime::ContextDatabase,
            ) -> fugue_lifter_runtime::LiftingContext {
                fugue_lifter_runtime::LiftingContext::new(language, ninputs, context, UNIQUE_MASK)
            }

            #[inline]
            #[allow(unused_mut)]
            pub fn default_context() -> fugue_lifter_runtime::ContextDatabase {
                let mut context =
                    fugue_lifter_runtime::ContextDatabase::new(
                        ADDRESS_UPPER_BOUND,
                        ADDRESS_ALIGNMENT,
                    );

                #(#context_variable_registrations)*

                context
            }

            #(#variant_blocks)*
        });
    }
}
