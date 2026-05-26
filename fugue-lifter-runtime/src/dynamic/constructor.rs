use fugue_sleigh_language::symbol::sub_table::Constructor as SleighConstructor;

use crate::context::{ContextPostAction, ContextPreAction};
use crate::dynamic::install::Install;
use crate::dynamic::tables::Tables;
use crate::operand::Operand;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct Constructor {
    pub(crate) id: u16,
    pub(crate) context_pre_actions: Box<[ContextPreAction]>,
    pub(crate) context_post_actions: Box<[ContextPostAction]>,
    pub(crate) operands: Box<[Operand]>,
    pub(crate) result: Option<u16>,
    pub(crate) build_action: Option<u16>,
    pub(crate) print_pieces: Box<[PrintPiece]>,
    pub(crate) first_whitespace: Option<usize>,
    pub(crate) flow_through_index: Option<usize>,
    pub(crate) delay_slot_length: usize,
    pub(crate) minimum_length: usize,
}

impl Constructor {
    pub(crate) fn from_sleigh<'a>(
        ctor: &'a SleighConstructor,
        id: u16,
        tables: &mut Tables<'a>,
    ) -> Self {
        let print_pieces = ctor
            .print_pieces()
            .iter()
            .map(|piece| {
                if piece.as_bytes().first() == Some(&b'\n') {
                    PrintPiece::Operand(u16::from(piece.as_bytes()[1] - b'A'))
                } else {
                    PrintPiece::Token(Box::<str>::from(piece.as_str()))
                }
            })
            .collect::<Box<[PrintPiece]>>();

        let operands = tables.build_operands(ctor);
        let (context_pre_actions, context_post_actions) = tables.build_context_actions(ctor);
        let result = ctor
            .template()
            .and_then(|tmpl| tmpl.result())
            .map(|tmpl| tables.handle_tpl(tmpl));
        let build_action = ctor.template().map(|tmpl| tables.construct_tpl(tmpl));

        Self {
            id,
            context_pre_actions,
            context_post_actions,
            operands,
            result,
            build_action,
            print_pieces,
            first_whitespace: ctor.first_whitespace(),
            flow_through_index: ctor.flow_through_index(),
            delay_slot_length: ctor
                .template()
                .map(|tmpl| tmpl.delay_slot())
                .unwrap_or_default(),
            minimum_length: ctor.minimum_length(),
        }
    }
}

impl Install for Constructor {
    type Target = crate::constructor::Constructor;

    fn install(self) -> Self::Target {
        let Self {
            id,
            context_pre_actions,
            context_post_actions,
            operands,
            result,
            build_action,
            print_pieces,
            first_whitespace,
            flow_through_index,
            delay_slot_length,
            minimum_length,
        } = self;
        Self::Target {
            id,
            context_pre_actions: context_pre_actions.install(),
            context_post_actions: context_post_actions.install(),
            operands: operands.install(),
            result,
            build_action,
            print_pieces: print_pieces.install(),
            first_whitespace,
            flow_through_index,
            delay_slot_length,
            minimum_length,
        }
    }
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum PrintPiece {
    Operand(u16),
    Token(Box<str>),
}

impl Install for PrintPiece {
    type Target = crate::constructor::PrintPiece;

    fn install(self) -> Self::Target {
        match self {
            Self::Operand(idx) => Self::Target::Operand(idx),
            Self::Token(token) => Self::Target::Token(token.install()),
        }
    }
}
