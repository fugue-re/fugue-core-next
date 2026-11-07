use fugue_sleigh_language::construct::{
    ConstTpl, ConstructTpl, HandleKind, HandleTpl, OpTpl, VarnodeTpl,
};
use fugue_sleigh_language::opcode::Opcode;
use fugue_sleigh_language::Language;
use proc_macro2::TokenStream;
use quote::quote;

use crate::core::Tables;

pub(crate) struct TplAdaptor<'a, 'b, T> {
    language: &'a Language,
    tpl: &'a T,
    tables: &'b mut Tables<'a>,
}

impl<'a, 'b, T> TplAdaptor<'a, 'b, T> {
    pub(crate) fn new(language: &'a Language, tpl: &'a T, tables: &'b mut Tables<'a>) -> Self {
        Self {
            language,
            tpl,
            tables,
        }
    }
}

impl<'a, 'b> TplAdaptor<'a, 'b, ConstructTpl> {
    pub(crate) fn tokens(&mut self) -> u16 {
        let delay_slot = u8::try_from(self.tpl.delay_slot()).expect("delay slot fits in u8");
        let labels = u8::try_from(self.tpl.labels()).expect("labels fits in u8");
        let result = self.tpl.result().map_or_else(
            || quote! { None },
            |tpl| {
                let tpl = TplAdaptor::new(&self.language, tpl, &mut self.tables).tokens();
                quote! { Some(#tpl) }
            },
        );
        let operations = self
            .tpl
            .operations()
            .iter()
            .map(|tpl| TplAdaptor::new(&self.language, tpl, &mut self.tables).tokens());

        let tpl = quote! {
            fugue_lifter_runtime::template::ConstructTpl {
                delay_slot: #delay_slot,
                labels: #labels,
                result: #result,
                operations: &[#(#operations),*],
            }
        };

        self.tables.push_construct_tpl(self.tpl, tpl)
    }
}

impl<'a, 'b> TplAdaptor<'a, 'b, HandleTpl> {
    pub(crate) fn tokens(&mut self) -> u16 {
        let space = TplAdaptor::new(&self.language, self.tpl.space(), &mut self.tables).tokens();
        let size = TplAdaptor::new(&self.language, self.tpl.size(), &mut self.tables).tokens();
        let ptr_space =
            TplAdaptor::new(&self.language, self.tpl.ptr_space(), &mut self.tables).tokens();
        let ptr_offset =
            TplAdaptor::new(&self.language, self.tpl.ptr_offset(), &mut self.tables).tokens();
        let ptr_size =
            TplAdaptor::new(&self.language, self.tpl.ptr_size(), &mut self.tables).tokens();
        let tmp_space =
            TplAdaptor::new(&self.language, self.tpl.tmp_space(), &mut self.tables).tokens();
        let tmp_offset =
            TplAdaptor::new(&self.language, self.tpl.tmp_offset(), &mut self.tables).tokens();

        self.tables.push_handle_tpl(
            self.tpl,
            quote! {
                fugue_lifter_runtime::template::HandleTpl {
                    space: #space,
                    size: #size,
                    ptr_space: #ptr_space,
                    ptr_offset: #ptr_offset,
                    ptr_size: #ptr_size,
                    tmp_space: #tmp_space,
                    tmp_offset: #tmp_offset,
                }
            },
        )
    }
}

impl<'a, 'b> TplAdaptor<'a, 'b, ConstTpl> {
    pub(crate) fn tokens(&mut self) -> u16 {
        use ConstTpl as C;
        use HandleKind as H;

        self.tables.push_const_tpl(
            self.tpl,
            match self.tpl {
                C::Real(val) => quote! { fugue_lifter_runtime::template::ConstTpl::Real(#val) },
                C::Handle(index, kind) => {
                    let kind = match kind {
                        H::Space => quote! { fugue_lifter_runtime::template::HandleKind::Space },
                        H::Offset => quote! { fugue_lifter_runtime::template::HandleKind::Offset },
                        H::Size => quote! { fugue_lifter_runtime::template::HandleKind::Size },
                        H::OffsetPlus(val) => {
                            quote! { fugue_lifter_runtime::template::HandleKind::OffsetPlus(#val) }
                        }
                    };
                    quote! { fugue_lifter_runtime::template::ConstTpl::Handle(#index, #kind) }
                }
                C::Start => quote! { fugue_lifter_runtime::template::ConstTpl::Start },
                C::Next => quote! { fugue_lifter_runtime::template::ConstTpl::Next },
                C::Next2 => quote! { fugue_lifter_runtime::template::ConstTpl::Next2 },
                C::CurrentSpace => {
                    quote! { fugue_lifter_runtime::template::ConstTpl::CurrentSpace }
                }
                C::CurrentSpaceSize => {
                    quote! { fugue_lifter_runtime::template::ConstTpl::CurrentSpaceSize }
                }
                C::SpaceId(id) => {
                    let id = id.index() as u8;
                    quote! { fugue_lifter_runtime::template::ConstTpl::SpaceId(#id) }
                }
                C::Relative(val) => {
                    quote! { fugue_lifter_runtime::template::ConstTpl::Relative(#val) }
                }
                _ => unimplemented!("flow operations not supported"),
            },
        )
    }
}

impl<'a, 'b> TplAdaptor<'a, 'b, OpTpl> {
    pub(crate) fn tokens(&mut self) -> u16 {
        use Opcode as O;

        let issue = |op: TokenStream| {
            quote! { fugue_lifter_runtime::template::Op::Issue(fugue_lifter_runtime::pcode::Op::#op) }
        };
        let space = || match self.tpl.inputs()[0].offset() {
            ConstTpl::SpaceId(space) => space.index() as u8,
            _ => unreachable!("load and store spaces are constant"),
        };
        let op = match self.tpl.opcode() {
            O::Load => {
                let space = space();
                issue(quote! { Load(#space) })
            }
            O::Store => {
                let space = space();
                issue(quote! { Store(#space) })
            }
            O::CallOther => {
                let ConstTpl::Real(index) = self.tpl.inputs()[0].offset() else {
                    unreachable!("user-defined operation indices are constant")
                };
                let index = *index as u16;
                let count = self.tpl.inputs().len() as u8 - 1;
                issue(quote! { UserOp(#index, #count) })
            }
            O::Copy => issue(quote! { Copy }),
            O::Branch => issue(quote! { Branch }),
            O::CBranch => issue(quote! { CBranch }),
            O::IBranch => issue(quote! { IBranch }),
            O::Call => issue(quote! { Call }),
            O::ICall => issue(quote! { ICall }),
            O::Return => issue(quote! { Return }),
            O::IntEq => issue(quote! { IntEq }),
            O::IntNotEq => issue(quote! { IntNotEq }),
            O::IntSLess => issue(quote! { IntSignedLess }),
            O::IntSLessEq => issue(quote! { IntSignedLessEq }),
            O::IntLess => issue(quote! { IntLess }),
            O::IntLessEq => issue(quote! { IntLessEq }),
            O::IntZExt => issue(quote! { ZeroExt }),
            O::IntSExt => issue(quote! { SignExt }),
            O::IntNeg => issue(quote! { IntNeg }),
            O::IntNot => issue(quote! { IntNot }),
            O::IntAdd => issue(quote! { IntAdd }),
            O::IntSub => issue(quote! { IntSub }),
            O::IntMul => issue(quote! { IntMul }),
            O::IntDiv => issue(quote! { IntDiv }),
            O::IntSDiv => issue(quote! { IntSignedDiv }),
            O::IntRem => issue(quote! { IntRem }),
            O::IntSRem => issue(quote! { IntSignedRem }),
            O::IntCarry => issue(quote! { IntCarry }),
            O::IntSCarry => issue(quote! { IntSignedCarry }),
            O::IntSBorrow => issue(quote! { IntSignedBorrow }),
            O::IntAnd => issue(quote! { IntAnd }),
            O::IntOr => issue(quote! { IntOr }),
            O::IntXor => issue(quote! { IntXor }),
            O::IntLShift => issue(quote! { IntLeftShift }),
            O::IntRShift => issue(quote! { IntRightShift }),
            O::IntSRShift => issue(quote! { IntSignedRightShift }),
            O::BoolNot => issue(quote! { BoolNot }),
            O::BoolAnd => issue(quote! { BoolAnd }),
            O::BoolOr => issue(quote! { BoolOr }),
            O::BoolXor => issue(quote! { BoolXor }),
            O::FloatEq => issue(quote! { FloatEq }),
            O::FloatNotEq => issue(quote! { FloatNotEq }),
            O::FloatLess => issue(quote! { FloatLess }),
            O::FloatLessEq => issue(quote! { FloatLessEq }),
            O::FloatIsNaN => issue(quote! { FloatIsNaN }),
            O::FloatAdd => issue(quote! { FloatAdd }),
            O::FloatSub => issue(quote! { FloatSub }),
            O::FloatMul => issue(quote! { FloatMul }),
            O::FloatDiv => issue(quote! { FloatDiv }),
            O::FloatNeg => issue(quote! { FloatNeg }),
            O::FloatAbs => issue(quote! { FloatAbs }),
            O::FloatSqrt => issue(quote! { FloatSqrt }),
            O::FloatOfInt => issue(quote! { IntToFloat }),
            O::FloatOfFloat => issue(quote! { FloatToFloat }),
            O::FloatTruncate => issue(quote! { FloatToInt }),
            O::FloatCeiling => issue(quote! { FloatCeiling }),
            O::FloatFloor => issue(quote! { FloatFloor }),
            O::FloatRound => issue(quote! { FloatRound }),
            O::Subpiece => issue(quote! { Subpiece }),
            O::PopCount => issue(quote! { CountOnes }),
            O::LZCount => issue(quote! { CountLeadingZeros }),
            O::Build => quote! { fugue_lifter_runtime::template::Op::Build },
            O::DelaySlot => quote! { fugue_lifter_runtime::template::Op::DelaySlot },
            O::Label => quote! { fugue_lifter_runtime::template::Op::Label },
            O::CrossBuild => quote! { fugue_lifter_runtime::template::Op::CrossBuild },
            O::Piece | O::Cast | O::SegmentOp | O::CPoolRef | O::New | O::Insert | O::Extract => {
                unreachable!("opcode is not emitted by the SLEIGH compiler")
            }
        };

        let output = self.tpl.output().map_or_else(
            || quote! { None },
            |tpl| {
                let tpl = TplAdaptor::new(&self.language, tpl, &mut self.tables).tokens();
                quote! { Some(#tpl) }
            },
        );

        let inputs = self
            .tpl
            .inputs()
            .iter()
            .map(|tpl| TplAdaptor::new(&self.language, tpl, &mut self.tables).tokens());

        let tpl = quote! {
            fugue_lifter_runtime::template::OpTpl {
                op: #op,
                inputs: &[#(#inputs),*],
                output: #output,
            }
        };

        self.tables.push_op_tpl(self.tpl, tpl)
    }
}

impl<'a, 'b> TplAdaptor<'a, 'b, VarnodeTpl> {
    pub(crate) fn tokens(&mut self) -> u16 {
        let tpl = match (self.tpl.space(), self.tpl.offset(), self.tpl.size()) {
            (ConstTpl::SpaceId(space), ConstTpl::Real(offset), ConstTpl::Real(size)) => {
                let space = space.index() as u8;
                let size = *size as u16;
                quote! {
                    fugue_lifter_runtime::template::VarnodeTpl::Fixed {
                        space: #space,
                        offset: #offset,
                        size: #size,
                    }
                }
            }
            (space, offset, size) => {
                let space = TplAdaptor::new(&self.language, space, &mut self.tables).tokens();
                let offset = TplAdaptor::new(&self.language, offset, &mut self.tables).tokens();
                let size = TplAdaptor::new(&self.language, size, &mut self.tables).tokens();
                quote! {
                    fugue_lifter_runtime::template::VarnodeTpl::Computed {
                        space: #space,
                        offset: #offset,
                        size: #size,
                    }
                }
            }
        };

        self.tables.push_varnode_tpl(self.tpl, tpl)
    }
}
