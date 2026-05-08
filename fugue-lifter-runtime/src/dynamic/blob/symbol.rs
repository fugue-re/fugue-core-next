use crate::pattern::PatternExpression;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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
