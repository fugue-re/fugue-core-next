use fugue_sleigh_language::symbol::sub_table::Context as SleighContext;
use fugue_sleigh_language::symbol::Symbol as SleighSymbol;
use fugue_sleigh_language::Language as SleighLanguage;

use crate::context::{ContextPostAction, ContextPostActionHandle, ContextPreAction};
use crate::dynamic::build::pattern::pattern_expression;
use crate::dynamic::build::Tables;

pub(super) fn convert_pre_action(
    language: &SleighLanguage,
    context: &SleighContext,
    tables: &mut Tables<'_>,
) -> ContextPreAction {
    let SleighContext::Operator {
        num,
        shift,
        mask,
        pattern_value,
    } = context
    else {
        unreachable!("convert_pre_action requires Context::Operator");
    };

    let value = pattern_expression(language, pattern_value, tables);
    ContextPreAction {
        num: *num,
        shift: *shift,
        mask: *mask,
        value,
    }
}

pub(super) fn convert_post_action(
    language: &SleighLanguage,
    context: &SleighContext,
    tables: &mut Tables<'_>,
) -> ContextPostAction {
    let SleighContext::Commit {
        symbol_id,
        num,
        mask,
        flow,
    } = context
    else {
        unreachable!("convert_post_action requires Context::Commit");
    };

    let symbol = language
        .symbol_table()
        .symbol(*symbol_id)
        .expect("valid symbol");

    let handle = if let SleighSymbol::Operand { handle_index, .. } = symbol {
        let opid = u16::try_from(*handle_index).expect("handle index fits in u16");
        ContextPostActionHandle::Operand(opid)
    } else {
        let symbol_idx = tables.symbol_for(*symbol_id);
        ContextPostActionHandle::Symbol(symbol_idx)
    };

    let space = language.spaces().default_space_ref();
    ContextPostAction {
        handle,
        num: *num,
        mask: *mask,
        highest: space.highest_offset(),
        word_size: space.word_size() as u64,
        flow: *flow,
    }
}
