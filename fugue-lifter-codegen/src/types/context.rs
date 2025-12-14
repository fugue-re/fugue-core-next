use fugue_sleigh_language::symbol::sub_table::Context;
use fugue_sleigh_language::symbol::Symbol;
use fugue_sleigh_language::Language;

use proc_macro2::TokenStream;
use quote::quote;

use crate::core::Tables;
use crate::types::pattern::PatternExpressionAdaptor;

pub(crate) struct ContextAdaptor<'a> {
    language: &'a Language,
    context: &'a Context,
    tables: &'a mut Tables,
}

impl<'a> ContextAdaptor<'a> {
    pub(crate) fn new(
        language: &'a Language,
        context: &'a Context,
        tables: &'a mut Tables,
    ) -> Self {
        Self {
            language,
            context,
            tables,
        }
    }

    pub(crate) fn context_action_tokens(&mut self) -> TokenStream {
        use Context as C;

        let value = match self.context {
            C::Operator {
                num,
                shift,
                mask,
                pattern_value,
            } => {
                let num = *num;
                let shift = *shift;
                let mask = *mask;
                let value =
                    PatternExpressionAdaptor::new(&self.language, pattern_value, &mut self.tables)
                        .pattern_expression_tokens();

                quote! {
                    fugue_lifter_runtime::context::ContextPreAction {
                        num: #num,
                        shift: #shift,
                        mask: #mask,
                        value: #value,
                    }
                }
            }
            C::Commit {
                symbol_id,
                num,
                mask,
                flow,
            } => {
                let symbol = self
                    .language
                    .symbol_table()
                    .symbol(*symbol_id)
                    .expect("valid symbol");

                let handle = if let Symbol::Operand { handle_index, .. } = symbol {
                    let opid = *handle_index;
                    quote! { fugue_lifter_runtime::context::ContextPostActionHandle::Operand(#opid) }
                } else {
                    let symbol = self.tables.symbol_for(*symbol_id);
                    quote! { fugue_lifter_runtime::context::ContextPostActionHandle::Symbol(#symbol) }
                };

                let space = self.language.spaces().default_space_ref();
                let word_size = space.word_size() as u64;
                let highest = space.highest_offset();
                let flow = *flow;

                // NOTE: when we apply the pre-context actions, we perform extraction operations
                // based on post actions.
                quote! {
                    fugue_lifter_runtime::context::ContextPostAction {
                        handle: #handle,
                        num: #num,
                        mask: #mask,
                        highest: #highest,
                        word_size: #word_size,
                        flow: #flow,
                    }
                }
            }
        };

        value
    }
}
