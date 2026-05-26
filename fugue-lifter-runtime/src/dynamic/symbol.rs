use fugue_sleigh_language::Language as SleighLanguage;
use fugue_sleigh_language::symbol::Symbol as SleighSymbol;

use crate::dynamic::install::Install;
use crate::dynamic::tables::Tables;
use crate::pattern::PatternExpression;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum Symbol {
    Epsilon,
    Value {
        pattern_value: PatternExpression,
    },
    ValueMap {
        pattern_value: PatternExpression,
        value_table: Box<[Option<i64>]>,
    },
    ValueMapFilled {
        pattern_value: PatternExpression,
        value_table: Box<[i64]>,
    },
    Name {
        pattern_value: PatternExpression,
        symbol_table: Box<[Option<Box<str>>]>,
    },
    Varnode {
        name: Box<str>,
        space: u8,
        offset: u64,
        size: u16,
    },
    VarnodeList {
        pattern_value: PatternExpression,
        varnode_table: Box<[Option<u16>]>,
        symbol_table: Box<[Option<Box<str>>]>,
    },
    VarnodeListFilled {
        pattern_value: PatternExpression,
        varnode_table: Box<[u16]>,
        symbol_table: Box<[Box<str>]>,
    },
    Operand {
        handle_index: usize,
    },
    Start {
        space: u8,
        size: u16,
    },
    End {
        space: u8,
        size: u16,
    },
    Next2 {
        space: u8,
        size: u16,
    },
}

impl Symbol {
    pub(crate) fn from_sleigh(symbol: &SleighSymbol, tables: &mut Tables<'_>) -> Option<Self> {
        use SleighSymbol as S;

        Some(match symbol {
            S::Epsilon { .. } => Self::Epsilon,
            S::Value { pattern_value, .. } => Self::Value {
                pattern_value: tables.pattern_expression(pattern_value),
            },
            S::ValueMap {
                pattern_value,
                value_table,
                table_is_filled,
                ..
            } => {
                let pattern_value = tables.pattern_expression(pattern_value);
                if *table_is_filled {
                    Self::ValueMapFilled {
                        pattern_value,
                        value_table: value_table.iter().copied().collect(),
                    }
                } else {
                    let entries = value_table
                        .iter()
                        .copied()
                        .map(|v| (v != 0xbadbeef).then_some(v));
                    Self::ValueMap {
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
                let pattern_value = tables.pattern_expression(pattern_value);
                let symbol_table = name_table
                    .iter()
                    .map(|v| (v != "\t").then(|| Box::<str>::from(v.as_str())))
                    .collect();
                Self::Name {
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
            } => Self::Varnode {
                name: Box::<str>::from(name.as_ref()),
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
                let pattern_value = tables.pattern_expression(pattern_value);
                if *table_is_filled {
                    let varnode_table_ids = varnode_table
                        .iter()
                        .copied()
                        .map(|id| tables.symbol_for(id.expect("table is filled")))
                        .collect::<Box<[u16]>>();
                    let symbol_table = varnode_table
                        .iter()
                        .copied()
                        .map(|id| {
                            let name = tables
                                .language()
                                .symbol_table()
                                .symbol(id.expect("table is filled"))
                                .expect("valid symbol")
                                .name();
                            Box::<str>::from(name)
                        })
                        .collect::<Box<[Box<str>]>>();
                    Self::VarnodeListFilled {
                        pattern_value,
                        varnode_table: varnode_table_ids,
                        symbol_table,
                    }
                } else {
                    let varnode_table_ids = varnode_table
                        .iter()
                        .copied()
                        .map(|id| id.map(|id| tables.symbol_for(id)))
                        .collect::<Box<[Option<u16>]>>();
                    let symbol_table = varnode_table
                        .iter()
                        .copied()
                        .map(|id| {
                            id.map(|id| {
                                let name = tables
                                    .language()
                                    .symbol_table()
                                    .symbol(id)
                                    .expect("valid symbol")
                                    .name();
                                Box::<str>::from(name)
                            })
                        })
                        .collect::<Box<[Option<Box<str>>]>>();
                    Self::VarnodeList {
                        pattern_value,
                        varnode_table: varnode_table_ids,
                        symbol_table,
                    }
                }
            }
            S::Operand { handle_index, .. } => Self::Operand {
                handle_index: *handle_index,
            },
            S::Start { .. } => {
                Self::default_space(tables.language(), |space, size| Self::Start { space, size })
            }
            S::End { .. } => {
                Self::default_space(tables.language(), |space, size| Self::End { space, size })
            }
            S::Next2 { .. } => {
                Self::default_space(tables.language(), |space, size| Self::Next2 { space, size })
            }
            _ => return None,
        })
    }

    fn default_space(language: &SleighLanguage, build: impl FnOnce(u8, u16) -> Self) -> Self {
        let space = language.spaces().default_space_ref();
        build(space.index() as u8, space.address_size() as u16)
    }
}

impl Install for Symbol {
    type Target = crate::symbol::Symbol;

    fn install(self) -> Self::Target {
        match self {
            Self::Epsilon => Self::Target::Epsilon,
            Self::Value { pattern_value } => Self::Target::Value { pattern_value },
            Self::ValueMap {
                pattern_value,
                value_table,
            } => Self::Target::ValueMap {
                pattern_value,
                value_table: value_table.install(),
            },
            Self::ValueMapFilled {
                pattern_value,
                value_table,
            } => Self::Target::ValueMapFilled {
                pattern_value,
                value_table: value_table.install(),
            },
            Self::Name {
                pattern_value,
                symbol_table,
            } => Self::Target::Name {
                pattern_value,
                symbol_table: symbol_table.install(),
            },
            Self::Varnode {
                name,
                space,
                offset,
                size,
            } => Self::Target::Varnode {
                name: name.install(),
                space,
                offset,
                size,
            },
            Self::VarnodeList {
                pattern_value,
                varnode_table,
                symbol_table,
            } => Self::Target::VarnodeList {
                pattern_value,
                varnode_table: varnode_table.install(),
                symbol_table: symbol_table.install(),
            },
            Self::VarnodeListFilled {
                pattern_value,
                varnode_table,
                symbol_table,
            } => Self::Target::VarnodeListFilled {
                pattern_value,
                varnode_table: varnode_table.install(),
                symbol_table: symbol_table.install(),
            },
            Self::Operand { handle_index } => Self::Target::Operand { handle_index },
            Self::Start { space, size } => Self::Target::Start { space, size },
            Self::End { space, size } => Self::Target::End { space, size },
            Self::Next2 { space, size } => Self::Target::Next2 { space, size },
        }
    }
}
