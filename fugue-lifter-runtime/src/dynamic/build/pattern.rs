use fugue_sleigh_language::pattern::PatternExpression as SleighPatternExpression;
use fugue_sleigh_language::symbol::Symbol as SleighSymbol;
use fugue_sleigh_language::Language as SleighLanguage;

use crate::dynamic::build::Tables;
use crate::pattern::{OperandOffset, PatternExpression, PatternOp};

pub(super) fn pattern_expression(
    language: &SleighLanguage,
    expression: &SleighPatternExpression,
    tables: &mut Tables<'_>,
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
                let symbols = language.symbol_table();
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
                let operand = language.symbol_table().symbol(operand_sym_id).unwrap();

                let ctor_id = u16::try_from(tables.ctor_for(*table_id, *scope, *constructor_id))
                    .expect("constructor id fits in u16");
                let value = pattern_expression(language, pexpr, tables);

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

    let reversed = nops.into_iter().rev().collect::<Vec<_>>();
    let (spos, epos) = tables.extend_pattern_ops(reversed.into_iter());
    PatternExpression::new(spos, epos)
}
