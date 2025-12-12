use fugue_sleigh_language::pattern::PatternExpression;
use fugue_sleigh_language::symbol::Symbol;
use fugue_sleigh_language::Language;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};

use crate::core::Tables;

pub(crate) struct PatternExpressionAdaptor<'a> {
    language: &'a Language,
    expression: &'a PatternExpression,
    tables: &'a Tables,
}

impl<'a> PatternExpressionAdaptor<'a> {
    pub(crate) fn new(
        language: &'a Language,
        expression: &'a PatternExpression,
        tables: &'a Tables,
    ) -> Self {
        Self {
            language,
            expression,
            tables,
        }
    }

    pub(crate) fn wrap(&self, expression: &'a PatternExpression) -> Self {
        Self {
            language: self.language,
            expression,
            tables: self.tables,
        }
    }

    // To translate, we do the following:
    //
    // Input: Add(Add(B, C), Sub(D, E))
    //
    // Output:
    //
    // [push(Add), push(rhs), push(lhs)]
    //
    // Expands to:
    //
    // [push(Add), push(Sub), push(E), push(D), push(Add), push(C), push(B)]
    //
    // We evaluate from right to left (reversing the list):
    //
    // push B | stack = [B]
    // push C | stack = [B, C]
    // add    | stack = [B + C]
    // push D | stack = [B + C, D]
    // push E | stack = [B + C, D, E]
    // add    | stack = [B + C, D - E]
    // add    | stack = [(B + C) + (D - E)]
    //
    fn to_stack(&self) -> Vec<TokenStream> {
        let mut stack = Vec::new();
        let mut queue = vec![self.expression];

        while let Some(expr) = queue.pop() {
            use PatternExpression as E;

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
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::TokenField {
                            big_endian: #big_endian,
                            sign_bit: #sign_bit,
                            bit_start: #bit_start,
                            bit_end: #bit_end,
                            byte_start: #byte_start,
                            byte_end: #byte_end,
                            shift: #shift,
                        }
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
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::ContextField {
                            sign_bit: #sign_bit,
                            bit_start: #bit_start,
                            bit_end: #bit_end,
                            byte_start: #byte_start,
                            byte_end: #byte_end,
                            shift: #shift,
                        }
                    });
                }
                E::Constant { value } => {
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Constant { value: #value }
                    });
                }
                E::Operand {
                    index,
                    table_id,
                    constructor_id,
                } => {
                    let symbols = self.language.symbol_table();
                    let table = symbols.symbol(*table_id).unwrap();
                    let Symbol::Subtable {
                        constructors,
                        scope,
                        ..
                    } = table
                    else {
                        unreachable!("this state should not be reachable");
                    };
                    let ctor = &constructors[*constructor_id];

                    let Symbol::Operand {
                        def_expr,
                        subsym_id,
                        ..
                    } = symbols.symbol(ctor.operand(*index)).unwrap()
                    else {
                        unreachable!("this state should not be reachable");
                    };

                    let pexpr = if let Some(def_expr) = def_expr.as_ref() {
                        def_expr
                    } else if let Some(subsym_id) = subsym_id.as_ref() {
                        let sym = symbols.symbol(*subsym_id).unwrap();
                        sym.pattern_value()
                    } else {
                        stack.push(quote! {
                            fugue_lifter_runtime::pattern::PatternOp::Constant { value: 0i64 }
                        });
                        continue;
                    };

                    let index = *index;
                    let symbol = ctor.operand(index);
                    let operand = self.language.symbol_table().symbol(symbol).unwrap();

                    let ctor_id = self.tables.ctor_for(*table_id, *scope, *constructor_id);
                    let value = self.wrap(pexpr);

                    let rel_offset = operand.relative_offset() as u8;
                    let offset = if operand.offset_base().is_none() {
                        quote! {
                            fugue_lifter_runtime::pattern::OperandOffset::Relative(#rel_offset)
                        }
                    } else {
                        let index = index as u8;
                        quote! {
                            fugue_lifter_runtime::pattern::OperandOffset::Operand(#index)
                        }
                    };

                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Operand {
                            constructor: #ctor_id,
                            offset: #offset,
                            value: #value,
                        }
                    });
                }
                E::StartInstruction => {
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::StartInstruction
                    });
                }
                E::EndInstruction => {
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::EndInstruction
                    });
                }
                E::Next2Instruction => {
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Next2Instruction
                    });
                }
                E::Plus(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Plus
                    });
                }
                E::Sub(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Sub
                    });
                }
                E::Mult(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Mult
                    });
                }
                E::Div(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Div
                    });
                }
                E::LeftShift(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::LeftShift
                    });
                }
                E::RightShift(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::RightShift
                    });
                }
                E::And(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::And
                    });
                }
                E::Or(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Or
                    });
                }
                E::Xor(lhs, rhs) => {
                    queue.push(lhs);
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Xor
                    });
                }
                E::Minus(rhs) => {
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Minus
                    });
                }
                E::Not(rhs) => {
                    queue.push(rhs);
                    stack.push(quote! {
                        fugue_lifter_runtime::pattern::PatternOp::Not
                    });
                }
            }
        }

        stack.reverse();
        stack
    }
}

impl<'a> ToTokens for PatternExpressionAdaptor<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ops = self.to_stack();
        tokens.extend(quote! {
            &[#(#ops),*]
        });
    }
}
