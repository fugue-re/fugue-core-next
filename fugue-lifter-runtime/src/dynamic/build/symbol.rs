use fugue_sleigh_language::symbol::Symbol as SleighSymbol;
use fugue_sleigh_language::Language as SleighLanguage;

use crate::dynamic::blob;
use crate::dynamic::build::pattern::pattern_expression;
use crate::dynamic::build::Tables;
use crate::operand::{OperandHandleResolver, OperandResolver};

pub(super) fn convert_symbol(
    language: &SleighLanguage,
    symbol: &SleighSymbol,
    tables: &mut Tables<'_>,
) -> Option<blob::symbol::Symbol> {
    use SleighSymbol as S;

    Some(match symbol {
        S::Epsilon { .. } => blob::symbol::Symbol::Epsilon,
        S::Value { pattern_value, .. } => blob::symbol::Symbol::Value {
            pattern_value: pattern_expression(language, pattern_value, tables),
        },
        S::ValueMap {
            pattern_value,
            value_table,
            table_is_filled,
            ..
        } => {
            let pattern_value = pattern_expression(language, pattern_value, tables);
            if *table_is_filled {
                blob::symbol::Symbol::ValueMapFilled {
                    pattern_value,
                    value_table: value_table.iter().copied().collect(),
                }
            } else {
                let entries =
                    value_table.iter().copied().map(
                        |v| {
                            if v == 0xbadbeef {
                                None
                            } else {
                                Some(v)
                            }
                        },
                    );
                blob::symbol::Symbol::ValueMap {
                    pattern_value,
                    value_table: entries.collect(),
                }
            }
        }
        S::Name {
            pattern_value,
            name_table,
            ..
        } => {
            let pattern_value = pattern_expression(language, pattern_value, tables);
            let symbol_table = name_table
                .iter()
                .map(|v| {
                    if v == "\t" {
                        None
                    } else {
                        Some(String::from(v.as_str()).into_boxed_str())
                    }
                })
                .collect();
            blob::symbol::Symbol::Name {
                pattern_value,
                symbol_table,
            }
        }
        S::Varnode {
            name,
            space,
            offset,
            size,
            ..
        } => blob::symbol::Symbol::Varnode {
            name: String::from(&**name).into_boxed_str(),
            space: space.index() as u8,
            offset: *offset,
            size: *size as u16,
        },
        S::VarnodeList {
            pattern_value,
            varnode_table,
            table_is_filled,
            ..
        } => {
            let pattern_value = pattern_expression(language, pattern_value, tables);
            if *table_is_filled {
                let values = varnode_table
                    .iter()
                    .copied()
                    .map(|id| tables.symbol_for(id.expect("table is filled")))
                    .collect::<Box<[u16]>>();
                let symbols = varnode_table
                    .iter()
                    .copied()
                    .map(|id| {
                        let name = language
                            .symbol_table()
                            .symbol(id.expect("table is filled"))
                            .expect("valid symbol")
                            .name();
                        String::from(name).into_boxed_str()
                    })
                    .collect::<Box<[Box<str>]>>();
                blob::symbol::Symbol::VarnodeListFilled {
                    pattern_value,
                    varnode_table: values,
                    symbol_table: symbols,
                }
            } else {
                let values = varnode_table
                    .iter()
                    .copied()
                    .map(|id| id.map(|id| tables.symbol_for(id)))
                    .collect::<Box<[Option<u16>]>>();
                let symbols = varnode_table
                    .iter()
                    .copied()
                    .map(|id| {
                        id.map(|id| {
                            let name = language
                                .symbol_table()
                                .symbol(id)
                                .expect("valid symbol")
                                .name();
                            String::from(name).into_boxed_str()
                        })
                    })
                    .collect::<Box<[Option<Box<str>>]>>();
                blob::symbol::Symbol::VarnodeList {
                    pattern_value,
                    varnode_table: values,
                    symbol_table: symbols,
                }
            }
        }
        S::Operand { handle_index, .. } => blob::symbol::Symbol::Operand {
            handle_index: *handle_index,
        },
        S::Start { .. } => {
            let space = language.spaces().default_space_ref();
            blob::symbol::Symbol::Start {
                space: space.index() as u8,
                size: space.address_size() as u16,
            }
        }
        S::End { .. } => {
            let space = language.spaces().default_space_ref();
            blob::symbol::Symbol::End {
                space: space.index() as u8,
                size: space.address_size() as u16,
            }
        }
        S::Next2 { .. } => {
            let space = language.spaces().default_space_ref();
            blob::symbol::Symbol::Next2 {
                space: space.index() as u8,
                size: space.address_size() as u16,
            }
        }
        _ => return None,
    })
}

pub(super) fn convert_operand_filter(
    language: &SleighLanguage,
    symbol: &SleighSymbol,
    tables: &mut Tables<'_>,
) -> Option<blob::operand::OperandFilter> {
    use SleighSymbol as S;

    match symbol {
        S::Name {
            pattern_value,
            name_table,
            table_is_filled,
            ..
        } if !*table_is_filled => {
            let bad = name_table
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    if v == "\t" {
                        Some(u16::try_from(i).expect("bad index fits in u16"))
                    } else {
                        None
                    }
                })
                .collect::<Box<[u16]>>();
            let limit = u16::try_from(name_table.len()).expect("limit fits in u16");
            let pattern = pattern_expression(language, pattern_value, tables);
            Some(blob::operand::OperandFilter {
                pattern,
                indices: bad,
                limit,
            })
        }
        S::ValueMap {
            pattern_value,
            value_table,
            table_is_filled,
            ..
        } if !*table_is_filled => {
            let bad = value_table
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    if *v == 0xbadbeef {
                        Some(u16::try_from(i).expect("bad index fits in u16"))
                    } else {
                        None
                    }
                })
                .collect::<Box<[u16]>>();
            let limit = u16::try_from(value_table.len()).expect("limit fits in u16");
            let pattern = pattern_expression(language, pattern_value, tables);
            Some(blob::operand::OperandFilter {
                pattern,
                indices: bad,
                limit,
            })
        }
        S::VarnodeList {
            pattern_value,
            varnode_table,
            table_is_filled,
            ..
        } if !*table_is_filled => {
            let bad = varnode_table
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    if v.is_none() {
                        Some(u16::try_from(i).expect("bad index fits in u16"))
                    } else {
                        None
                    }
                })
                .collect::<Box<[u16]>>();
            let limit = u16::try_from(varnode_table.len()).expect("limit fits in u16");
            let pattern = pattern_expression(language, pattern_value, tables);
            Some(blob::operand::OperandFilter {
                pattern,
                indices: bad,
                limit,
            })
        }
        _ => None,
    }
}

pub(super) fn operand_resolvers(
    language: &SleighLanguage,
    operand: &SleighSymbol,
    tables: &mut Tables<'_>,
) -> (OperandResolver, OperandHandleResolver) {
    if let Some(target) = operand.defining_symbol(language.symbol_table()) {
        match target {
            SleighSymbol::Subtable { id, scope, .. } => {
                let dtree = u16::try_from(tables.subtable_id_mapping[&(*id, *scope)])
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
                    let filter = u16::try_from(tables.operand_filter_id_mapping[id])
                        .expect("operand filter id fits in u16");
                    OperandResolver::Filter(filter)
                };
                let symbol =
                    u16::try_from(tables.symbol_id_mapping[id]).expect("symbol id fits in u16");
                (resolver, OperandHandleResolver::Symbol(symbol))
            }
            other => {
                let id = other.id();
                let symbol =
                    u16::try_from(tables.symbol_id_mapping[&id]).expect("symbol id fits in u16");
                (OperandResolver::None, OperandHandleResolver::Symbol(symbol))
            }
        }
    } else {
        let pexp = operand.defining_expression().unwrap();
        let value = pattern_expression(language, pexp, tables);
        (
            OperandResolver::None,
            OperandHandleResolver::Expression(value),
        )
    }
}
