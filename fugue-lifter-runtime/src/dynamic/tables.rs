use std::collections::BTreeMap;
use std::hash::Hash;

use fugue_sleigh_language::Language as SleighLanguage;
use fugue_sleigh_language::construct::{
    self as sleigh_construct, ConstTpl as SleighConstTpl, ConstructTpl as SleighConstructTpl,
    HandleKind as SleighHandleKind, HandleTpl as SleighHandleTpl, OpTpl as SleighOpTpl,
    VarnodeTpl as SleighVarnodeTpl,
};
use fugue_sleigh_language::opcode::Opcode;
use fugue_sleigh_language::pattern::PatternExpression as SleighPatternExpression;
use fugue_sleigh_language::symbol::Symbol as SleighSymbol;
use fugue_sleigh_language::symbol::sub_table::{
    Constructor as SleighConstructor, Context as SleighContext, DecisionNode as SleighDecisionNode,
};
use indexmap::IndexMap;

use crate::context::{ContextPostAction, ContextPostActionHandle, ContextPreAction};
use crate::dynamic::constructor::Constructor;
use crate::dynamic::operand::OperandFilter;
use crate::dynamic::resolve::{DecisionNode, DecisionPair};
use crate::dynamic::symbol::Symbol;
use crate::dynamic::template::{ConstructTpl, OpTpl};
use crate::operand::{Operand, OperandHandleResolver, OperandResolver};
use crate::pattern::{OperandOffset, PatternExpression, PatternOp};
use crate::template::{ConstTpl, HandleKind, HandleTpl, Op, VarnodeTpl};

pub(crate) struct Tables<'a> {
    pub(crate) language: &'a SleighLanguage,

    pub(crate) ctors: Vec<Constructor>,
    pub(crate) dtrees: Vec<DecisionNode>,
    pub(crate) operand_filters: Vec<OperandFilter>,
    pub(crate) pattern_ops: Vec<PatternOp>,
    pub(crate) symbols: Vec<Symbol>,

    pub(crate) const_tpls: IndexMap<&'a sleigh_construct::ConstTpl, ConstTpl>,
    pub(crate) construct_tpls: IndexMap<&'a sleigh_construct::ConstructTpl, ConstructTpl>,
    pub(crate) handle_tpls: IndexMap<&'a sleigh_construct::HandleTpl, HandleTpl>,
    pub(crate) op_tpls: IndexMap<&'a sleigh_construct::OpTpl, OpTpl>,
    pub(crate) varnode_tpls: IndexMap<&'a sleigh_construct::VarnodeTpl, VarnodeTpl>,

    pub(crate) ctor_id_mapping: BTreeMap<(usize, usize, usize), usize>,
    pub(crate) operand_filter_id_mapping: BTreeMap<usize, usize>,
    pub(crate) subtable_id_mapping: BTreeMap<(usize, usize), usize>,
    pub(crate) symbol_id_mapping: BTreeMap<usize, usize>,

    pub(crate) context_variables: Vec<(Box<str>, usize, usize)>,
}

impl<'a> Tables<'a> {
    pub(crate) fn new(language: &'a SleighLanguage) -> Self {
        let mut tables = Self {
            language,
            ctors: Vec::new(),
            dtrees: Vec::new(),
            operand_filters: Vec::new(),
            pattern_ops: Vec::new(),
            symbols: Vec::new(),
            const_tpls: IndexMap::new(),
            construct_tpls: IndexMap::new(),
            handle_tpls: IndexMap::new(),
            op_tpls: IndexMap::new(),
            varnode_tpls: IndexMap::new(),
            ctor_id_mapping: BTreeMap::new(),
            operand_filter_id_mapping: BTreeMap::new(),
            subtable_id_mapping: BTreeMap::new(),
            symbol_id_mapping: BTreeMap::new(),
            context_variables: Vec::new(),
        };
        tables.assign_indices();
        tables.build_symbols_and_subtables();
        tables.collect_context_variables();
        tables
    }

    pub(crate) fn language(&self) -> &'a SleighLanguage {
        self.language
    }

    pub(crate) fn ctor_for(&self, id: usize, scope: usize, ctor: usize) -> usize {
        self.ctor_id_mapping[&(id, scope, ctor)]
    }

    pub(crate) fn symbol_for(&self, sym_id: usize) -> u16 {
        u16::try_from(self.symbol_id_mapping[&sym_id]).expect("symbol id fits in u16")
    }

    pub(crate) fn root_dtree_id(&self) -> u16 {
        u16::try_from(self.subtable_id_mapping[&(0, 0)]).expect("root decision tree id fits in u16")
    }

    pub(crate) fn const_tpl(&mut self, tpl: &'a SleighConstTpl) -> u16 {
        let value = match tpl {
            SleighConstTpl::Real(val) => ConstTpl::Real(*val),
            SleighConstTpl::Handle(index, kind) => {
                let kind = match kind {
                    SleighHandleKind::Space => HandleKind::Space,
                    SleighHandleKind::Offset => HandleKind::Offset,
                    SleighHandleKind::Size => HandleKind::Size,
                    SleighHandleKind::OffsetPlus(val) => HandleKind::OffsetPlus(*val),
                };
                ConstTpl::Handle(*index, kind)
            }
            SleighConstTpl::Start => ConstTpl::Start,
            SleighConstTpl::Next => ConstTpl::Next,
            SleighConstTpl::Next2 => ConstTpl::Next2,
            SleighConstTpl::CurrentSpace => ConstTpl::CurrentSpace,
            SleighConstTpl::CurrentSpaceSize => ConstTpl::CurrentSpaceSize,
            SleighConstTpl::SpaceId(id) => ConstTpl::SpaceId(id.index() as u8),
            SleighConstTpl::Relative(val) => ConstTpl::Relative(*val),
            _ => panic!("flow operations are not supported by the dynamic builder"),
        };
        intern(&mut self.const_tpls, tpl, value)
    }

    pub(crate) fn handle_tpl(&mut self, tpl: &'a SleighHandleTpl) -> u16 {
        let space = self.const_tpl(tpl.space());
        let size = self.const_tpl(tpl.size());
        let ptr_space = self.const_tpl(tpl.ptr_space());
        let ptr_offset = self.const_tpl(tpl.ptr_offset());
        let ptr_size = self.const_tpl(tpl.ptr_size());
        let tmp_space = self.const_tpl(tpl.tmp_space());
        let tmp_offset = self.const_tpl(tpl.tmp_offset());

        intern(
            &mut self.handle_tpls,
            tpl,
            HandleTpl {
                space,
                size,
                ptr_space,
                ptr_offset,
                ptr_size,
                tmp_space,
                tmp_offset,
            },
        )
    }

    pub(crate) fn varnode_tpl(&mut self, tpl: &'a SleighVarnodeTpl) -> u16 {
        let space = self.const_tpl(tpl.space());
        let offset = self.const_tpl(tpl.offset());
        let size = self.const_tpl(tpl.size());
        intern(
            &mut self.varnode_tpls,
            tpl,
            VarnodeTpl {
                space,
                offset,
                size,
            },
        )
    }

    pub(crate) fn op_tpl(&mut self, tpl: &'a SleighOpTpl) -> u16 {
        let op = tpl.opcode().into();
        let inputs = tpl
            .inputs()
            .iter()
            .map(|input| self.varnode_tpl(input))
            .collect::<Box<[u16]>>();
        let output = tpl.output().map(|out| self.varnode_tpl(out));

        intern(&mut self.op_tpls, tpl, OpTpl { op, inputs, output })
    }

    pub(crate) fn construct_tpl(&mut self, tpl: &'a SleighConstructTpl) -> u16 {
        let delay_slot = u8::try_from(tpl.delay_slot()).expect("delay slot fits in u8");
        let labels = u8::try_from(tpl.labels()).expect("labels fits in u8");
        let result = tpl.result().map(|res| self.handle_tpl(res));
        let operations = tpl
            .operations()
            .iter()
            .map(|op| self.op_tpl(op))
            .collect::<Box<[u16]>>();

        intern(
            &mut self.construct_tpls,
            tpl,
            ConstructTpl {
                delay_slot,
                labels,
                result,
                operations,
            },
        )
    }

    pub(crate) fn pattern_expression(
        &mut self,
        expression: &SleighPatternExpression,
    ) -> PatternExpression {
        let mut queue = vec![expression];
        let mut nops = Vec::new();

        while let Some(expr) = queue.pop() {
            use SleighPatternExpression as E;
            match expr {
                E::TokenField {
                    big_endian,
                    sign_bit,
                    bit_start,
                    bit_end,
                    byte_start,
                    byte_end,
                    shift,
                } => {
                    nops.push(PatternOp::TokenField {
                        big_endian: *big_endian,
                        sign_bit: *sign_bit,
                        bit_start: u8::try_from(*bit_start).expect("bit_start fits in u8"),
                        bit_end: u8::try_from(*bit_end).expect("bit_end fits in u8"),
                        byte_start: u8::try_from(*byte_start).expect("byte_start fits in u8"),
                        byte_end: u8::try_from(*byte_end).expect("byte_end fits in u8"),
                        shift: u8::try_from(*shift).expect("shift fits in u8"),
                    });
                }
                E::ContextField {
                    sign_bit,
                    bit_start,
                    bit_end,
                    byte_start,
                    byte_end,
                    shift,
                } => {
                    nops.push(PatternOp::ContextField {
                        sign_bit: *sign_bit,
                        bit_start: u8::try_from(*bit_start).expect("bit_start fits in u8"),
                        bit_end: u8::try_from(*bit_end).expect("bit_end fits in u8"),
                        byte_start: u8::try_from(*byte_start).expect("byte_start fits in u8"),
                        byte_end: u8::try_from(*byte_end).expect("byte_end fits in u8"),
                        shift: u8::try_from(*shift).expect("shift fits in u8"),
                    });
                }
                E::Constant { value } => {
                    nops.push(PatternOp::Constant { value: *value });
                }
                E::Operand {
                    index,
                    table_id,
                    constructor_id,
                } => {
                    let symbols = self.language.symbol_table();
                    let table = symbols.symbol(*table_id).unwrap();
                    let SleighSymbol::Subtable {
                        constructors,
                        scope,
                        ..
                    } = table
                    else {
                        unreachable!("operand pattern table must be a subtable");
                    };
                    let ctor = &constructors[*constructor_id];
                    let SleighSymbol::Operand {
                        def_expr,
                        subsym_id,
                        ..
                    } = symbols.symbol(ctor.operand(*index)).unwrap()
                    else {
                        unreachable!("operand symbol must be Operand kind");
                    };

                    let pexpr = if let Some(def_expr) = def_expr.as_ref() {
                        def_expr
                    } else if let Some(subsym_id) = subsym_id.as_ref() {
                        let sym = symbols.symbol(*subsym_id).unwrap();
                        sym.pattern_value()
                    } else {
                        nops.push(PatternOp::Constant { value: 0 });
                        continue;
                    };

                    let operand_index = *index;
                    let operand_sym_id = ctor.operand(operand_index);
                    let operand = self.language.symbol_table().symbol(operand_sym_id).unwrap();

                    let ctor_id = u16::try_from(self.ctor_for(*table_id, *scope, *constructor_id))
                        .expect("constructor id fits in u16");
                    let value = self.pattern_expression(pexpr);

                    let rel_offset =
                        u8::try_from(operand.relative_offset()).expect("rel_offset fits in u8");
                    let offset = if operand.offset_base().is_none() {
                        OperandOffset::Relative(rel_offset)
                    } else {
                        OperandOffset::Operand(
                            u8::try_from(operand_index).expect("operand index fits in u8"),
                        )
                    };

                    nops.push(PatternOp::Operand {
                        constructor: ctor_id,
                        offset,
                        value,
                    });
                }
                E::StartInstruction => nops.push(PatternOp::StartInstruction),
                E::EndInstruction => nops.push(PatternOp::EndInstruction),
                E::Next2Instruction => nops.push(PatternOp::Next2Instruction),
                E::Plus(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::Plus);
                }
                E::Sub(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::Sub);
                }
                E::Mult(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::Mult);
                }
                E::Div(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::Div);
                }
                E::LeftShift(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::LeftShift);
                }
                E::RightShift(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::RightShift);
                }
                E::And(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::And);
                }
                E::Or(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::Or);
                }
                E::Xor(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    nops.push(PatternOp::Xor);
                }
                E::Minus(rhs) => {
                    queue.push(rhs);
                    nops.push(PatternOp::Minus);
                }
                E::Not(rhs) => {
                    queue.push(rhs);
                    nops.push(PatternOp::Not);
                }
            }
        }

        let (spos, epos) = self.extend_pattern_ops(nops.into_iter().rev());
        PatternExpression::new(spos, epos)
    }

    pub(crate) fn pre_action(&mut self, context: &SleighContext) -> ContextPreAction {
        let SleighContext::Operator {
            num,
            shift,
            mask,
            pattern_value,
        } = context
        else {
            unreachable!("pre_action requires Context::Operator");
        };

        let value = self.pattern_expression(pattern_value);
        ContextPreAction {
            num: *num,
            shift: *shift,
            mask: *mask,
            value,
        }
    }

    pub(crate) fn post_action(&mut self, context: &SleighContext) -> ContextPostAction {
        let SleighContext::Commit {
            symbol_id,
            num,
            mask,
            flow,
        } = context
        else {
            unreachable!("post_action requires Context::Commit");
        };

        let symbol = self
            .language
            .symbol_table()
            .symbol(*symbol_id)
            .expect("valid symbol");

        let handle = if let SleighSymbol::Operand { handle_index, .. } = symbol {
            let opid = u16::try_from(*handle_index).expect("handle index fits in u16");
            ContextPostActionHandle::Operand(opid)
        } else {
            ContextPostActionHandle::Symbol(self.symbol_for(*symbol_id))
        };

        let space = self.language.spaces().default_space_ref();
        ContextPostAction {
            handle,
            num: *num,
            mask: *mask,
            highest: space.highest_offset(),
            word_size: space.word_size() as u64,
            flow: *flow,
        }
    }

    pub(crate) fn build_operands(&mut self, ctor: &SleighConstructor) -> Box<[Operand]> {
        let mut operands = Vec::with_capacity(ctor.operand_count());

        for oid in 0..ctor.operand_count() {
            let operand_sym_id = ctor.operand(oid);
            let operand = self.language.symbol_table().symbol(operand_sym_id).unwrap();

            let offset_base = operand.offset_base();
            let offset_rela = operand.relative_offset();
            let minimum_length = if let SleighSymbol::Operand { min_length, .. } = operand {
                *min_length
            } else {
                unreachable!("operand has Operand kind")
            };

            let (resolver, handle_resolver) = self.operand_resolvers(operand);

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

    pub(crate) fn build_context_actions(
        &mut self,
        ctor: &SleighConstructor,
    ) -> (Box<[ContextPreAction]>, Box<[ContextPostAction]>) {
        let mut pre = Vec::new();
        let mut post = Vec::new();
        for action in ctor.context().iter() {
            match action {
                SleighContext::Operator { .. } => {
                    pre.push(self.pre_action(action));
                }
                SleighContext::Commit { .. } => {
                    post.push(self.post_action(action));
                }
            }
        }
        (pre.into_boxed_slice(), post.into_boxed_slice())
    }

    pub(crate) fn operand_resolvers(
        &mut self,
        operand: &SleighSymbol,
    ) -> (OperandResolver, OperandHandleResolver) {
        if let Some(target) = operand.defining_symbol(self.language.symbol_table()) {
            match target {
                SleighSymbol::Subtable { id, scope, .. } => {
                    let dtree = u16::try_from(self.subtable_id_mapping[&(*id, *scope)])
                        .expect("decision tree id fits in u16");
                    (
                        OperandResolver::Constructor(dtree),
                        OperandHandleResolver::None,
                    )
                }
                SleighSymbol::ValueMap {
                    id,
                    table_is_filled,
                    ..
                }
                | SleighSymbol::VarnodeList {
                    id,
                    table_is_filled,
                    ..
                }
                | SleighSymbol::Name {
                    id,
                    table_is_filled,
                    ..
                } => {
                    let resolver = if *table_is_filled {
                        OperandResolver::None
                    } else {
                        let filter = u16::try_from(self.operand_filter_id_mapping[id])
                            .expect("operand filter id fits in u16");
                        OperandResolver::Filter(filter)
                    };
                    let symbol =
                        u16::try_from(self.symbol_id_mapping[id]).expect("symbol id fits in u16");
                    (resolver, OperandHandleResolver::Symbol(symbol))
                }
                other => {
                    let id = other.id();
                    let symbol =
                        u16::try_from(self.symbol_id_mapping[&id]).expect("symbol id fits in u16");
                    (OperandResolver::None, OperandHandleResolver::Symbol(symbol))
                }
            }
        } else {
            let pexp = operand.defining_expression().unwrap();
            let value = self.pattern_expression(pexp);
            (
                OperandResolver::None,
                OperandHandleResolver::Expression(value),
            )
        }
    }

    fn assign_indices(&mut self) {
        let symtab = self.language.symbol_table();
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

    fn build_symbols_and_subtables(&mut self) {
        for symbol in self.language.symbol_table().symbols().iter() {
            if let SleighSymbol::Subtable {
                id,
                scope,
                constructors,
                decision_tree,
                ..
            } = symbol
            {
                self.generate_subtable(*id, *scope, constructors, decision_tree);
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

            if let Some(converted) = Symbol::from_sleigh(symbol, self) {
                self.symbols.push(converted);
            }
            if let Some(filter) = OperandFilter::from_sleigh(symbol, self) {
                self.operand_filters.push(filter);
            }
        }
    }

    fn collect_context_variables(&mut self) {
        let symtab = self.language.symbol_table();
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
                    Box::<str>::from(name.as_str()),
                    *bit_start,
                    *bit_end,
                ));
            }
        }
    }

    fn generate_subtable(
        &mut self,
        id: usize,
        scope: usize,
        ctors: &'a [SleighConstructor],
        dtree: &'a SleighDecisionNode,
    ) {
        for (cid, ctor) in ctors.iter().enumerate() {
            let mapped_id =
                u16::try_from(self.ctor_for(id, scope, cid)).expect("constructor id fits in u16");
            let constructor = Constructor::from_sleigh(ctor, mapped_id, self);
            self.ctors.push(constructor);
        }

        self.flatten_decision_tree(id, scope, dtree);
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
            .map(|pat| DecisionPair::from_sleigh(self, id, scope, pat))
            .collect::<Box<[DecisionPair]>>();

        let mut children_ids = Vec::with_capacity(dtree.children().len());
        for child in dtree.children() {
            children_ids.push(self.flatten_decision_tree(id, scope, child));
        }

        let dtree_id = self.dtrees.len();
        self.dtrees.push(DecisionNode {
            start_bit: dtree.start_bit() as u32,
            size: dtree.size() as u32,
            context_decision: dtree.context_decision(),
            patterns,
            children: children_ids.into_boxed_slice(),
        });

        u16::try_from(dtree_id).expect("decision tree id fits in u16")
    }

    fn extend_pattern_ops(&mut self, iter: impl ExactSizeIterator<Item = PatternOp>) -> (u16, u16) {
        let spos = self.pattern_ops.len();
        self.pattern_ops.extend(iter);
        let epos = self.pattern_ops.len();
        let spos = u16::try_from(spos).expect("pattern op start fits in u16");
        let epos = u16::try_from(epos).expect("pattern op end fits in u16");
        (spos, epos)
    }
}

fn intern<K: Eq + Hash, V>(map: &mut IndexMap<K, V>, key: K, value: V) -> u16 {
    let idx = match map.get_index_of(&key) {
        Some(idx) => idx,
        None => map.insert_full(key, value).0,
    };
    u16::try_from(idx).expect("interned id fits in u16")
}

impl From<Opcode> for Op {
    fn from(opcode: Opcode) -> Self {
        use Opcode as O;
        match opcode {
            O::Copy => Op::Copy,
            O::Load => Op::Load,
            O::Store => Op::Store,
            O::Branch => Op::Branch,
            O::CBranch => Op::CBranch,
            O::IBranch => Op::IBranch,
            O::Call => Op::Call,
            O::ICall => Op::ICall,
            O::CallOther => Op::CallOther,
            O::Return => Op::Return,
            O::IntEq => Op::IntEq,
            O::IntNotEq => Op::IntNotEq,
            O::IntSLess => Op::IntSLess,
            O::IntSLessEq => Op::IntSLessEq,
            O::IntLess => Op::IntLess,
            O::IntLessEq => Op::IntLessEq,
            O::IntZExt => Op::IntZExt,
            O::IntSExt => Op::IntSExt,
            O::IntNeg => Op::IntNeg,
            O::IntNot => Op::IntNot,
            O::IntAdd => Op::IntAdd,
            O::IntSub => Op::IntSub,
            O::IntMul => Op::IntMul,
            O::IntDiv => Op::IntDiv,
            O::IntSDiv => Op::IntSDiv,
            O::IntRem => Op::IntRem,
            O::IntSRem => Op::IntSRem,
            O::IntCarry => Op::IntCarry,
            O::IntSCarry => Op::IntSCarry,
            O::IntSBorrow => Op::IntSBorrow,
            O::IntAnd => Op::IntAnd,
            O::IntOr => Op::IntOr,
            O::IntXor => Op::IntXor,
            O::IntLShift => Op::IntLShift,
            O::IntRShift => Op::IntRShift,
            O::IntSRShift => Op::IntSRShift,
            O::BoolNot => Op::BoolNot,
            O::BoolAnd => Op::BoolAnd,
            O::BoolOr => Op::BoolOr,
            O::BoolXor => Op::BoolXor,
            O::FloatEq => Op::FloatEq,
            O::FloatNotEq => Op::FloatNotEq,
            O::FloatLess => Op::FloatLess,
            O::FloatLessEq => Op::FloatLessEq,
            O::FloatIsNaN => Op::FloatIsNaN,
            O::FloatAdd => Op::FloatAdd,
            O::FloatSub => Op::FloatSub,
            O::FloatMul => Op::FloatMul,
            O::FloatDiv => Op::FloatDiv,
            O::FloatNeg => Op::FloatNeg,
            O::FloatAbs => Op::FloatAbs,
            O::FloatSqrt => Op::FloatSqrt,
            O::FloatOfInt => Op::FloatOfInt,
            O::FloatOfFloat => Op::FloatOfFloat,
            O::FloatTruncate => Op::FloatTruncate,
            O::FloatCeiling => Op::FloatCeiling,
            O::FloatFloor => Op::FloatFloor,
            O::FloatRound => Op::FloatRound,
            O::Build => Op::Build,
            O::DelaySlot => Op::DelaySlot,
            O::Piece => Op::Piece,
            O::Subpiece => Op::Subpiece,
            O::Cast => Op::Cast,
            O::Label => Op::Label,
            O::CrossBuild => Op::CrossBuild,
            O::SegmentOp => Op::SegmentOp,
            O::CPoolRef => Op::CPoolRef,
            O::New => Op::New,
            O::Insert => Op::Insert,
            O::Extract => Op::Extract,
            O::PopCount => Op::PopCount,
            O::LZCount => Op::LZCount,
        }
    }
}
