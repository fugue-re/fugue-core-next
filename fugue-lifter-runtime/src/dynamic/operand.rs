use fugue_sleigh_language::symbol::Symbol as SleighSymbol;

use crate::dynamic::install::Install;
use crate::dynamic::tables::Tables;
use crate::pattern::PatternExpression;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub(crate) struct OperandFilter {
    pub(crate) pattern: PatternExpression,
    pub(crate) indices: Box<[u16]>,
    pub(crate) limit: u16,
}

impl OperandFilter {
    pub(crate) fn from_sleigh(symbol: &SleighSymbol, tables: &mut Tables<'_>) -> Option<Self> {
        use SleighSymbol as S;

        let (pattern_value, indices, len) = match symbol {
            S::Name {
                pattern_value,
                name_table,
                table_is_filled,
                ..
            } if !*table_is_filled => {
                let indices = name_table
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| *v == "\t")
                    .map(|(i, _)| u16::try_from(i).expect("operand filter index fits in u16"))
                    .collect::<Box<[u16]>>();
                (pattern_value, indices, name_table.len())
            }
            S::ValueMap {
                pattern_value,
                value_table,
                table_is_filled,
                ..
            } if !*table_is_filled => {
                let indices = value_table
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| **v == 0xbadbeef)
                    .map(|(i, _)| u16::try_from(i).expect("operand filter index fits in u16"))
                    .collect::<Box<[u16]>>();
                (pattern_value, indices, value_table.len())
            }
            S::VarnodeList {
                pattern_value,
                varnode_table,
                table_is_filled,
                ..
            } if !*table_is_filled => {
                let indices = varnode_table
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.is_none())
                    .map(|(i, _)| u16::try_from(i).expect("operand filter index fits in u16"))
                    .collect::<Box<[u16]>>();
                (pattern_value, indices, varnode_table.len())
            }
            _ => return None,
        };

        let limit = u16::try_from(len).expect("operand filter limit fits in u16");
        let pattern = tables.pattern_expression(pattern_value);
        Some(Self {
            pattern,
            indices,
            limit,
        })
    }
}

impl Install for OperandFilter {
    type Target = crate::operand::OperandFilter;

    fn install(self) -> Self::Target {
        let Self {
            pattern,
            indices,
            limit,
        } = self;
        Self::Target {
            pattern,
            indices: indices.install(),
            limit,
        }
    }
}

