use fugue_sleigh_language::Language;
use fugue_sleigh_language::construct::{
    ConstTpl, ConstructTpl, HandleKind, HandleTpl, OpTpl, VarnodeTpl,
};
use fugue_sleigh_language::opcode::Opcode;
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

        let op = match self.tpl.opcode() {
            O::Copy => quote! { fugue_lifter_runtime::template::Op::Copy },
            O::Load => quote! { fugue_lifter_runtime::template::Op::Load },
            O::Store => quote! { fugue_lifter_runtime::template::Op::Store },
            O::Branch => quote! { fugue_lifter_runtime::template::Op::Branch },
            O::CBranch => quote! { fugue_lifter_runtime::template::Op::CBranch },
            O::IBranch => quote! { fugue_lifter_runtime::template::Op::IBranch },
            O::Call => quote! { fugue_lifter_runtime::template::Op::Call },
            O::ICall => quote! { fugue_lifter_runtime::template::Op::ICall },
            O::CallOther => quote! { fugue_lifter_runtime::template::Op::CallOther },
            O::Return => quote! { fugue_lifter_runtime::template::Op::Return },
            O::IntEq => quote! { fugue_lifter_runtime::template::Op::IntEq },
            O::IntNotEq => quote! { fugue_lifter_runtime::template::Op::IntNotEq },
            O::IntSLess => quote! { fugue_lifter_runtime::template::Op::IntSLess },
            O::IntSLessEq => quote! { fugue_lifter_runtime::template::Op::IntSLessEq },
            O::IntLess => quote! { fugue_lifter_runtime::template::Op::IntLess },
            O::IntLessEq => quote! { fugue_lifter_runtime::template::Op::IntLessEq },
            O::IntZExt => quote! { fugue_lifter_runtime::template::Op::IntZExt },
            O::IntSExt => quote! { fugue_lifter_runtime::template::Op::IntSExt },
            O::IntNeg => quote! { fugue_lifter_runtime::template::Op::IntNeg },
            O::IntNot => quote! { fugue_lifter_runtime::template::Op::IntNot },
            O::IntAdd => quote! { fugue_lifter_runtime::template::Op::IntAdd },
            O::IntSub => quote! { fugue_lifter_runtime::template::Op::IntSub },
            O::IntMul => quote! { fugue_lifter_runtime::template::Op::IntMul },
            O::IntDiv => quote! { fugue_lifter_runtime::template::Op::IntDiv },
            O::IntSDiv => quote! { fugue_lifter_runtime::template::Op::IntSDiv },
            O::IntRem => quote! { fugue_lifter_runtime::template::Op::IntRem },
            O::IntSRem => quote! { fugue_lifter_runtime::template::Op::IntSRem },
            O::IntCarry => quote! { fugue_lifter_runtime::template::Op::IntCarry },
            O::IntSCarry => quote! { fugue_lifter_runtime::template::Op::IntSCarry },
            O::IntSBorrow => quote! { fugue_lifter_runtime::template::Op::IntSBorrow },
            O::IntAnd => quote! { fugue_lifter_runtime::template::Op::IntAnd },
            O::IntOr => quote! { fugue_lifter_runtime::template::Op::IntOr },
            O::IntXor => quote! { fugue_lifter_runtime::template::Op::IntXor },
            O::IntLShift => quote! { fugue_lifter_runtime::template::Op::IntLShift },
            O::IntRShift => quote! { fugue_lifter_runtime::template::Op::IntRShift },
            O::IntSRShift => quote! { fugue_lifter_runtime::template::Op::IntSRShift },
            O::BoolNot => quote! { fugue_lifter_runtime::template::Op::BoolNot },
            O::BoolAnd => quote! { fugue_lifter_runtime::template::Op::BoolAnd },
            O::BoolOr => quote! { fugue_lifter_runtime::template::Op::BoolOr },
            O::BoolXor => quote! { fugue_lifter_runtime::template::Op::BoolXor },
            O::FloatEq => quote! { fugue_lifter_runtime::template::Op::FloatEq },
            O::FloatNotEq => quote! { fugue_lifter_runtime::template::Op::FloatNotEq },
            O::FloatLess => quote! { fugue_lifter_runtime::template::Op::FloatLess },
            O::FloatLessEq => quote! { fugue_lifter_runtime::template::Op::FloatLessEq },
            O::FloatIsNaN => quote! { fugue_lifter_runtime::template::Op::FloatIsNaN },
            O::FloatAdd => quote! { fugue_lifter_runtime::template::Op::FloatAdd },
            O::FloatSub => quote! { fugue_lifter_runtime::template::Op::FloatSub },
            O::FloatMul => quote! { fugue_lifter_runtime::template::Op::FloatMul },
            O::FloatDiv => quote! { fugue_lifter_runtime::template::Op::FloatDiv },
            O::FloatNeg => quote! { fugue_lifter_runtime::template::Op::FloatNeg },
            O::FloatAbs => quote! { fugue_lifter_runtime::template::Op::FloatAbs },
            O::FloatSqrt => quote! { fugue_lifter_runtime::template::Op::FloatSqrt },
            O::FloatOfInt => quote! { fugue_lifter_runtime::template::Op::FloatOfInt },
            O::FloatOfFloat => quote! { fugue_lifter_runtime::template::Op::FloatOfFloat },
            O::FloatTruncate => quote! { fugue_lifter_runtime::template::Op::FloatTruncate },
            O::FloatCeiling => quote! { fugue_lifter_runtime::template::Op::FloatCeiling },
            O::FloatFloor => quote! { fugue_lifter_runtime::template::Op::FloatFloor },
            O::FloatRound => quote! { fugue_lifter_runtime::template::Op::FloatRound },
            O::Build => quote! { fugue_lifter_runtime::template::Op::Build },
            O::DelaySlot => quote! { fugue_lifter_runtime::template::Op::DelaySlot },
            O::Piece => quote! { fugue_lifter_runtime::template::Op::Piece },
            O::Subpiece => quote! { fugue_lifter_runtime::template::Op::Subpiece },
            O::Cast => quote! { fugue_lifter_runtime::template::Op::Cast },
            O::Label => quote! { fugue_lifter_runtime::template::Op::Label },
            O::CrossBuild => quote! { fugue_lifter_runtime::template::Op::CrossBuild },
            O::SegmentOp => quote! { fugue_lifter_runtime::template::Op::SegmentOp },
            O::CPoolRef => quote! { fugue_lifter_runtime::template::Op::CPoolRef },
            O::New => quote! { fugue_lifter_runtime::template::Op::New },
            O::Insert => quote! { fugue_lifter_runtime::template::Op::Insert },
            O::Extract => quote! { fugue_lifter_runtime::template::Op::Extract },
            O::PopCount => quote! { fugue_lifter_runtime::template::Op::PopCount },
            O::LZCount => quote! { fugue_lifter_runtime::template::Op::LZCount },
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
        let space = TplAdaptor::new(&self.language, self.tpl.space(), &mut self.tables).tokens();
        let offset = TplAdaptor::new(&self.language, self.tpl.offset(), &mut self.tables).tokens();
        let size = TplAdaptor::new(&self.language, self.tpl.size(), &mut self.tables).tokens();

        self.tables.push_varnode_tpl(
            self.tpl,
            quote! {
                fugue_lifter_runtime::template::VarnodeTpl {
                    space: #space,
                    offset: #offset,
                    size: #size,
                }
            },
        )
    }
}
