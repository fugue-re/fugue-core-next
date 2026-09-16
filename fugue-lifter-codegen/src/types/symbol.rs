use fugue_sleigh_language::pattern::PatternExpression;
use fugue_sleigh_language::symbol::Symbol;
use fugue_sleigh_language::Language;
use proc_macro2::TokenStream;
use quote::quote;

use crate::core::Tables;
use crate::types::pattern::PatternExpressionAdaptor;

pub(crate) struct SymbolAdaptor<'a, 'b> {
    language: &'a Language,
    symbol: &'a Symbol,
    tables: &'b mut Tables<'a>,
}

impl<'a, 'b> SymbolAdaptor<'a, 'b> {
    pub(crate) fn new(
        language: &'a Language,
        symbol: &'a Symbol,
        tables: &'b mut Tables<'a>,
    ) -> Self {
        Self {
            language,
            symbol,
            tables,
        }
    }

    fn build_filter(
        &mut self,
        pattern: &'a PatternExpression,
        indices: impl Iterator<Item = usize>,
        limit: usize,
    ) -> TokenStream {
        let pvalue = PatternExpressionAdaptor::new(&self.language, pattern, &mut self.tables)
            .pattern_expression_tokens();
        let indices = indices.map(|i| u16::try_from(i).expect("index fits in u16"));
        let limit = u16::try_from(limit).expect("limit fits in u16");

        quote! {
            fugue_lifter_runtime::operand::OperandFilter {
                pattern: #pvalue,
                indices: &[#(#indices),*],
                limit: #limit,
            }
        }
    }

    pub(crate) fn operand_filter_tokens(&mut self) -> Option<TokenStream> {
        use Symbol as S;

        match self.symbol {
            S::Name {
                pattern_value,
                name_table,
                table_is_filled,
                ..
            } if !*table_is_filled => {
                let bad_indices = name_table.iter().enumerate().filter_map(|(i, v)| {
                    if v == "\t" {
                        Some(i)
                    } else {
                        None
                    }
                });
                let limit = name_table.len();

                Some(self.build_filter(pattern_value, bad_indices, limit))
            }
            S::ValueMap {
                pattern_value,
                value_table,
                table_is_filled,
                ..
            } if !*table_is_filled => {
                let bad_indices = value_table.iter().enumerate().filter_map(|(i, v)| {
                    if *v == 0xbadbeef {
                        Some(i)
                    } else {
                        None
                    }
                });
                let limit = value_table.len();

                Some(self.build_filter(pattern_value, bad_indices, limit))
            }
            S::VarnodeList {
                pattern_value,
                varnode_table,
                table_is_filled,
                ..
            } if !*table_is_filled => {
                let bad_indices = varnode_table.iter().enumerate().filter_map(|(i, v)| {
                    if v.is_none() {
                        Some(i)
                    } else {
                        None
                    }
                });
                let limit = varnode_table.len();

                Some(self.build_filter(pattern_value, bad_indices, limit))
            }
            _ => None,
        }
    }

    pub(crate) fn symbol_tokens(&mut self) -> Option<TokenStream> {
        use Symbol as S;

        let value = match self.symbol {
            S::Epsilon { .. } => quote! {
                fugue_lifter_runtime::symbol::Symbol::Epsilon
            },
            S::Value { pattern_value, .. } => {
                let pvalue =
                    PatternExpressionAdaptor::new(&self.language, pattern_value, &mut self.tables)
                        .pattern_expression_tokens();
                quote! {
                    fugue_lifter_runtime::symbol::Symbol::Value {
                        pattern_value: #pvalue,
                    }
                }
            }
            S::ValueMap {
                pattern_value,
                value_table,
                table_is_filled,
                ..
            } => {
                let pvalue =
                    PatternExpressionAdaptor::new(&self.language, pattern_value, &mut self.tables)
                        .pattern_expression_tokens();

                if *table_is_filled {
                    let values = value_table.iter().copied();

                    quote! {
                        fugue_lifter_runtime::symbol::Symbol::ValueMapFilled {
                            pattern_value: #pvalue,
                            value_table: &[#(#values),*],
                        }
                    }
                } else {
                    let values = value_table.iter().copied().map(|v| {
                        if v == 0xbadbeef {
                            quote! { None }
                        } else {
                            quote! { Some(#v) }
                        }
                    });

                    quote! {
                        fugue_lifter_runtime::symbol::Symbol::ValueMap {
                            pattern_value: #pvalue,
                            value_table: &[#(#values),*],
                        }
                    }
                }
            }
            S::Name {
                pattern_value,
                name_table,
                ..
            } => {
                // NOTE: we could merge those cases that are behaviourally similar
                let pvalue =
                    PatternExpressionAdaptor::new(&self.language, pattern_value, &mut self.tables)
                        .pattern_expression_tokens();
                let symbols = name_table.iter().map(|v| {
                    if v == "\t" {
                        quote! { None }
                    } else {
                        quote! { Some(#v) }
                    }
                });

                quote! {
                    fugue_lifter_runtime::symbol::Symbol::Name {
                        pattern_value: #pvalue,
                        symbol_table: &[#(#symbols),*],
                    }
                }
            }
            S::Varnode {
                name,
                space,
                offset,
                size,
                ..
            } => {
                let name = name.as_str();
                let space = space.index() as u8;
                let offset = *offset;
                let size = *size as u16;

                quote! {
                    fugue_lifter_runtime::symbol::Symbol::Varnode {
                        name: #name,
                        space: #space,
                        offset: #offset,
                        size: #size,
                    }
                }
            }
            S::VarnodeList {
                pattern_value,
                varnode_table,
                table_is_filled,
                ..
            } => {
                let pvalue =
                    PatternExpressionAdaptor::new(&self.language, pattern_value, &mut self.tables)
                        .pattern_expression_tokens();

                if *table_is_filled {
                    let values = varnode_table.iter().copied().map(|id| {
                        self.tables
                            .symbol_for(id.expect("table is filled") as usize)
                    });

                    // TODO: avoid the need to store the symbols
                    let symbols = varnode_table.iter().copied().map(|id| {
                        let name = self
                            .language
                            .symbol_table()
                            .symbol(id.expect("table is filled") as usize)
                            .expect("valid symbol")
                            .name();
                        quote! { #name }
                    });

                    quote! {
                        fugue_lifter_runtime::symbol::Symbol::VarnodeListFilled {
                            pattern_value: #pvalue,
                            varnode_table: &[#(#values),*],
                            symbol_table: &[#(#symbols),*],
                        }
                    }
                } else {
                    let values = varnode_table.iter().copied().map(|id| {
                        if let Some(id) = id {
                            let index = self.tables.symbol_for(id as usize);
                            quote! { Some(#index) }
                        } else {
                            quote! { None }
                        }
                    });

                    let symbols = varnode_table.iter().copied().map(|id| {
                        let Some(id) = id else {
                            return quote! { None };
                        };

                        let name = self
                            .language
                            .symbol_table()
                            .symbol(id)
                            .expect("valid symbol")
                            .name();

                        quote! { Some(#name) }
                    });

                    quote! {
                        fugue_lifter_runtime::symbol::Symbol::VarnodeList {
                            pattern_value: #pvalue,
                            varnode_table: &[#(#values),*],
                            symbol_table: &[#(#symbols),*],
                        }
                    }
                }
            }
            S::Operand { handle_index, .. } => {
                let handle_index = *handle_index;
                quote! {
                    fugue_lifter_runtime::symbol::Symbol::Operand {
                        handle_index: #handle_index,
                    }
                }
            }
            S::Start { .. } => {
                let space = self.language.spaces().default_space_ref();
                let id = space.index() as u8;
                let size = space.address_size() as u16;

                quote! {
                    fugue_lifter_runtime::symbol::Symbol::Start {
                        space: #id,
                        size: #size,
                    }
                }
            }
            S::End { .. } => {
                let space = self.language.spaces().default_space_ref();
                let id = space.index() as u8;
                let size = space.address_size() as u16;

                quote! {
                    fugue_lifter_runtime::symbol::Symbol::End {
                        space: #id,
                        size: #size,
                    }
                }
            }
            S::Next2 { .. } => {
                let space = self.language.spaces().default_space_ref();
                let id = space.index() as u8;
                let size = space.address_size() as u16;

                quote! {
                    fugue_lifter_runtime::symbol::Symbol::Next2 {
                        space: #id,
                        size: #size,
                    }
                }
            }
            _ => {
                return None;
            }
        };

        Some(value)
    }
}
