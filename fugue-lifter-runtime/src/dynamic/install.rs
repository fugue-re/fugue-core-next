use crate::constructor::{Constructor, PrintPiece};
use crate::data::{LanguageData, SpaceInfo};
use crate::dynamic::blob;
use crate::language::Language;
use crate::operand::OperandFilter;
use crate::resolve::{DecisionNode, DecisionPair, DisjointPattern, Pattern};
use crate::symbol::Symbol;
use crate::template::{ConstructTpl, OpTpl};

pub(crate) fn install(blob: blob::language::Language) -> &'static Language {
    let blob::language::Language {
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
    } = blob;

    let id = leak_str(id);
    let processor = leak_str(processor);
    let variant = leak_str(variant);

    let spaces = leak_slice_with(spaces, install_space_info);
    let space_word_sizes = leak_slice_map(spaces, |spc| spc.word_size);
    let space_upper_bounds = leak_slice_map(spaces, |spc| spc.upper_bound);

    let constructors = leak_slice_with(constructors, install_constructor);
    let decision_trees = leak_slice_with(decision_trees, install_decision_node);
    let operand_filters = leak_slice_with(operand_filters, install_operand_filter);
    let pattern_expressions = Box::leak(pattern_expressions);
    let symbols = leak_slice_with(symbols, install_symbol);

    let const_templates = Box::leak(const_templates);
    let construct_templates = leak_slice_with(construct_templates, install_construct_tpl);
    let handle_templates = Box::leak(handle_templates);
    let op_templates = leak_slice_with(op_templates, install_op_tpl);
    let varnode_templates = Box::leak(varnode_templates);

    let registers = leak_slice_with(registers, |(name, vnd)| (leak_str(name), vnd));
    let register_ranges =
        leak_slice_with(register_ranges, |(off, sz, name)| (off, sz, leak_str(name)));
    let user_ops = leak_slice_with(user_ops, leak_str);
    let space_names = leak_slice_with(space_names, leak_str);
    let context_vars = leak_slice_with(context_vars, |(name, range)| (leak_str(name), range));
    let context_defaults =
        leak_slice_with(context_defaults, |(name, value)| (leak_str(name), value));

    let language_data = Box::leak(Box::new(LanguageData {
        root_dtree,
        address_size,
        constant_space,
        default_space,
        unique_space,
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
    }));

    Box::leak(Box::new(Language {
        id,
        processor,
        little_endian,
        variant,
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
        registers,
        register_ranges,
        user_ops,
        space_names,
        context_vars,
        context_defaults,
        data: language_data,
    }))
}

fn leak_str(value: Box<str>) -> &'static str {
    Box::leak(value)
}

fn leak_slice_with<T, U, F>(values: Box<[T]>, f: F) -> &'static [U]
where
    F: FnMut(T) -> U,
{
    let mapped = Vec::from(values).into_iter().map(f).collect::<Box<[U]>>();
    Box::leak(mapped)
}

fn leak_slice_map<T, U: Copy, F>(values: &[T], f: F) -> &'static [U]
where
    F: FnMut(&T) -> U,
{
    let mapped = values.iter().map(f).collect::<Box<[U]>>();
    Box::leak(mapped)
}

fn install_space_info(value: blob::space::SpaceInfo) -> SpaceInfo {
    let blob::space::SpaceInfo {
        name,
        word_size,
        upper_bound,
        kind,
    } = value;
    SpaceInfo {
        name: leak_str(name),
        word_size,
        upper_bound,
        kind,
    }
}

fn install_constructor(value: blob::constructor::Constructor) -> Constructor {
    let blob::constructor::Constructor {
        id,
        context_pre_actions,
        context_post_actions,
        operands,
        result,
        build_action,
        print_pieces,
        first_whitespace,
        flow_through_index,
        delay_slot_length,
        minimum_length,
    } = value;
    Constructor {
        id,
        context_pre_actions: Box::leak(context_pre_actions),
        context_post_actions: Box::leak(context_post_actions),
        operands: Box::leak(operands),
        result,
        build_action,
        print_pieces: leak_slice_with(print_pieces, install_print_piece),
        first_whitespace,
        flow_through_index,
        delay_slot_length,
        minimum_length,
    }
}

fn install_print_piece(value: blob::constructor::PrintPiece) -> PrintPiece {
    match value {
        blob::constructor::PrintPiece::Operand(idx) => PrintPiece::Operand(idx),
        blob::constructor::PrintPiece::Token(token) => PrintPiece::Token(leak_str(token)),
    }
}

fn install_decision_node(value: blob::resolve::DecisionNode) -> DecisionNode {
    let blob::resolve::DecisionNode {
        start_bit,
        size,
        context_decision,
        patterns,
        children,
    } = value;
    DecisionNode {
        start_bit,
        size,
        context_decision,
        patterns: leak_slice_with(patterns, install_decision_pair),
        children: Box::leak(children),
    }
}

fn install_decision_pair(value: blob::resolve::DecisionPair) -> DecisionPair {
    let blob::resolve::DecisionPair {
        constructor,
        pattern,
    } = value;
    DecisionPair {
        constructor,
        pattern: install_disjoint_pattern(pattern),
    }
}

fn install_disjoint_pattern(value: blob::resolve::DisjointPattern) -> DisjointPattern {
    match value {
        blob::resolve::DisjointPattern::Context(pat) => {
            DisjointPattern::Context(install_pattern(pat))
        }
        blob::resolve::DisjointPattern::Instruction(pat) => {
            DisjointPattern::Instruction(install_pattern(pat))
        }
        blob::resolve::DisjointPattern::Combine {
            context,
            instruction,
        } => DisjointPattern::Combine {
            context: install_pattern(context),
            instruction: install_pattern(instruction),
        },
    }
}

fn install_pattern(value: blob::resolve::Pattern) -> Pattern {
    let blob::resolve::Pattern {
        offset,
        non_zero_size,
        masks,
        values,
    } = value;
    Pattern {
        offset,
        non_zero_size,
        masks: Box::leak(masks),
        values: Box::leak(values),
    }
}

fn install_operand_filter(value: blob::operand::OperandFilter) -> OperandFilter {
    let blob::operand::OperandFilter {
        pattern,
        indices,
        limit,
    } = value;
    OperandFilter {
        pattern,
        indices: Box::leak(indices),
        limit,
    }
}

fn install_symbol(value: blob::symbol::Symbol) -> Symbol {
    match value {
        blob::symbol::Symbol::Epsilon => Symbol::Epsilon,
        blob::symbol::Symbol::Value { pattern_value } => Symbol::Value { pattern_value },
        blob::symbol::Symbol::ValueMap {
            pattern_value,
            value_table,
        } => Symbol::ValueMap {
            pattern_value,
            value_table: Box::leak(value_table),
        },
        blob::symbol::Symbol::ValueMapFilled {
            pattern_value,
            value_table,
        } => Symbol::ValueMapFilled {
            pattern_value,
            value_table: Box::leak(value_table),
        },
        blob::symbol::Symbol::Name {
            pattern_value,
            symbol_table,
        } => Symbol::Name {
            pattern_value,
            symbol_table: leak_slice_with(symbol_table, |entry| entry.map(leak_str)),
        },
        blob::symbol::Symbol::Varnode {
            name,
            space,
            offset,
            size,
        } => Symbol::Varnode {
            name: leak_str(name),
            space,
            offset,
            size,
        },
        blob::symbol::Symbol::VarnodeList {
            pattern_value,
            varnode_table,
            symbol_table,
        } => Symbol::VarnodeList {
            pattern_value,
            varnode_table: Box::leak(varnode_table),
            symbol_table: leak_slice_with(symbol_table, |entry| entry.map(leak_str)),
        },
        blob::symbol::Symbol::VarnodeListFilled {
            pattern_value,
            varnode_table,
            symbol_table,
        } => Symbol::VarnodeListFilled {
            pattern_value,
            varnode_table: Box::leak(varnode_table),
            symbol_table: leak_slice_with(symbol_table, leak_str),
        },
        blob::symbol::Symbol::Operand { handle_index } => Symbol::Operand { handle_index },
        blob::symbol::Symbol::Start { space, size } => Symbol::Start { space, size },
        blob::symbol::Symbol::End { space, size } => Symbol::End { space, size },
        blob::symbol::Symbol::Next2 { space, size } => Symbol::Next2 { space, size },
    }
}

fn install_construct_tpl(value: blob::template::ConstructTpl) -> ConstructTpl {
    let blob::template::ConstructTpl {
        delay_slot,
        labels,
        result,
        operations,
    } = value;
    ConstructTpl {
        delay_slot,
        labels,
        result,
        operations: Box::leak(operations),
    }
}

fn install_op_tpl(value: blob::template::OpTpl) -> OpTpl {
    let blob::template::OpTpl { op, inputs, output } = value;
    OpTpl {
        op,
        inputs: Box::leak(inputs),
        output,
    }
}
