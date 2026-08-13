use std::borrow::Borrow;
use std::collections::HashMap;

use fugue_core::arch::Arch;
use fugue_core::il::common::{IlExprId, IlSourceSpan, IlValueId};
use fugue_core::il::ecode::ssa::{ECodeSsaDomain, ECodeSsaIr, ECodeSsaOp, ECodeSsaOpcode};
use fugue_core::il::ecode::{ECodeExprOpcode, ECodeIr, ECodeStmt, ECodeStmtOpcode};
use fugue_core::il::mcode::ssa::{MCodeSsaIr, MCodeSsaOp, MCodeSsaOpcode};
use fugue_core::il::mcode::{MCodeVarId, MCodeVarKind};
use fugue_core::il::pcode::{PCodeIr, PCodeLocationId, PCodeOp};
use fugue_core::ir::Address;
use fugue_core::lifter::{Lifter, Varnode};
use fugue_core::storage::{AddressSpaceId, DEFAULT_SPACE_ID};

use crate::bindings::{Address as BindingAddress, IlLine, IlToken, IlTokenKind};

const PREC_INFIX_MIN: u8 = 1;

pub struct IlRenderer {
    lifter: Lifter,
    register_space: u8,
    flags: HashMap<u64, &'static str>,
}

impl IlRenderer {
    pub fn new(arch: &Arch) -> Self {
        let lifter = arch.lifter();
        let register_space = lifter.register_space();
        let flags = arch
            .flags()
            .iter()
            .filter_map(|flag| {
                let varnode = flag.borrow();
                lifter
                    .register_name(varnode)
                    .map(|name| (varnode.offset, name))
            })
            .collect();

        Self {
            lifter,
            register_space,
            flags,
        }
    }

    fn ordered_addresses(&self, spans: &[IlSourceSpan]) -> Vec<Address> {
        let mut addresses = spans.iter().map(|span| span.address()).collect::<Vec<_>>();
        addresses.sort_by_key(Address::offset);
        addresses.dedup();
        addresses
    }

    fn opcode(mnemonic: &str) -> IlToken {
        IlToken::new(IlTokenKind::Opcode, mnemonic)
    }

    fn keyword(text: &str) -> IlToken {
        IlToken::new(IlTokenKind::Keyword, text)
    }

    fn punct(text: &str) -> IlToken {
        IlToken::new(IlTokenKind::Punctuation, text)
    }

    fn number(value: u64) -> IlToken {
        IlToken::new(IlTokenKind::Number, format!("{value:#x}"))
    }

    fn register(&self, offset: u64, bytes: u32) -> IlToken {
        let name = u16::try_from(bytes.max(1)).ok().and_then(|bytes| {
            let varnode = Varnode::new(self.register_space, offset, bytes);
            self.lifter.register_name(&varnode)
        });
        match name {
            Some(name) => IlToken::new(IlTokenKind::Register, name),
            None => IlToken::new(IlTokenKind::Register, format!("reg[{offset:#x}]"))
                .with_title(format!("register offset {offset:#x}, {bytes} bytes")),
        }
    }

    fn flag(&self, offset: u64) -> IlToken {
        match self.flags.get(&offset) {
            Some(name) => IlToken::new(IlTokenKind::Flag, *name),
            None => IlToken::new(IlTokenKind::Flag, format!("flag[{offset:#x}]")),
        }
    }

    fn intrinsic_meta(&self, id: u64) -> IlToken {
        let label = u16::try_from(id)
            .ok()
            .and_then(|id| self.lifter.user_op_by_id(id))
            .map(str::to_owned)
            .unwrap_or_else(|| id.to_string());
        IlToken::new(IlTokenKind::Meta, format!("<{label}>"))
    }

    fn space_label(index: usize) -> String {
        format!("mem<{index}>")
    }

    fn space(&self, space: AddressSpaceId) -> IlToken {
        IlToken::new(IlTokenKind::Space, Self::space_label(space.index()))
    }

    fn address_token(&self, offset: u64) -> IlToken {
        IlToken::new(IlTokenKind::Address, format!("{offset:#x}"))
            .with_nav(Address::new(DEFAULT_SPACE_ID, offset))
    }

    fn offset_meta(immediate: u64) -> IlToken {
        IlToken::new(IlTokenKind::Meta, format!("@{immediate}")).with_title("bit offset")
    }

    pub fn ecode(&self, ir: &ECodeIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for address in self.ordered_addresses(ir.source_spans()) {
            for (_, statement) in ir.statements_for_source(address) {
                let mut tokens = Vec::new();
                self.ecode_statement(ir, statement, &mut tokens);
                lines.push(IlLine {
                    address: BindingAddress::from(address),
                    tokens,
                });
            }
        }
        lines
    }

    fn ecode_statement(&self, ir: &ECodeIr, statement: &ECodeStmt, out: &mut Vec<IlToken>) {
        let operands = ir.statement_operands_for(statement);
        match statement.opcode() {
            ECodeStmtOpcode::WriteRegister => {
                let value = statement.value();
                let bytes = value.map(|id| self.expr_bytes(ir, id)).unwrap_or(0);
                out.push(self.register(statement.immediate(), u32::from(bytes)));
                out.push(Self::punct(" = "));
                self.ecode_value(ir, value, out);
            }
            ECodeStmtOpcode::WriteFlag => {
                out.push(self.flag(statement.immediate()));
                out.push(Self::punct(" = "));
                self.ecode_value(ir, statement.value(), out);
            }
            ECodeStmtOpcode::Store => {
                if let Some(space) = statement.address_space() {
                    out.push(self.space(space));
                }
                out.push(Self::punct("["));
                self.ecode_operand(ir, operands.first().copied(), out);
                out.push(Self::punct("] = "));
                self.ecode_operand(ir, operands.get(1).copied(), out);
            }
            ECodeStmtOpcode::Branch => {
                out.push(Self::keyword("goto"));
                out.push(Self::punct(" "));
                self.branch_target(statement, out);
            }
            ECodeStmtOpcode::Call => {
                out.push(Self::keyword("call"));
                out.push(Self::punct(" "));
                self.branch_target(statement, out);
            }
            ECodeStmtOpcode::ConditionalBranch => {
                out.push(Self::keyword("if"));
                out.push(Self::punct(" "));
                self.ecode_operand(ir, operands.first().copied(), out);
                out.push(Self::punct(" "));
                out.push(Self::keyword("goto"));
                out.push(Self::punct(" "));
                self.branch_target(statement, out);
            }
            ECodeStmtOpcode::BranchIndirect => {
                out.push(Self::keyword("goto"));
                out.push(Self::punct(" "));
                self.ecode_operand(ir, operands.first().copied(), out);
            }
            ECodeStmtOpcode::CallIndirect => {
                out.push(Self::keyword("call"));
                out.push(Self::punct(" "));
                self.ecode_operand(ir, operands.first().copied(), out);
            }
            ECodeStmtOpcode::Return => {
                out.push(Self::keyword("return"));
                if let Some(target) = operands.first().copied() {
                    out.push(Self::punct(" "));
                    self.ecode_expr(ir, target, out, 0);
                }
            }
            ECodeStmtOpcode::Intrinsic => {
                out.push(Self::opcode("intrinsic"));
                out.push(self.intrinsic_meta(statement.immediate()));
                self.ecode_args(ir, operands, out);
            }
            ECodeStmtOpcode::Trap => {
                out.push(Self::keyword("trap"));
            }
        }
    }

    fn branch_target(&self, statement: &ECodeStmt, out: &mut Vec<IlToken>) {
        match statement.address() {
            Some(address) => out.push(
                IlToken::new(IlTokenKind::Address, format!("{:#x}", address.offset()))
                    .with_nav(address),
            ),
            None => out.push(IlToken::new(IlTokenKind::Meta, "?")),
        }
    }

    fn ecode_args(&self, ir: &ECodeIr, operands: &[IlExprId], out: &mut Vec<IlToken>) {
        out.push(Self::punct("("));
        for (index, operand) in operands.iter().enumerate() {
            if index != 0 {
                out.push(Self::punct(", "));
            }
            self.ecode_expr(ir, *operand, out, 0);
        }
        out.push(Self::punct(")"));
    }

    fn ecode_operand(&self, ir: &ECodeIr, operand: Option<IlExprId>, out: &mut Vec<IlToken>) {
        match operand {
            Some(id) => self.ecode_expr(ir, id, out, 0),
            None => out.push(IlToken::new(IlTokenKind::Meta, "?")),
        }
    }

    fn ecode_value(&self, ir: &ECodeIr, value: Option<IlExprId>, out: &mut Vec<IlToken>) {
        self.ecode_operand(ir, value, out);
    }

    fn negated_addend(
        &self,
        ir: &ECodeIr,
        opcode: ECodeExprOpcode,
        addend: IlExprId,
    ) -> Option<u64> {
        if !matches!(opcode, ECodeExprOpcode::Add | ECodeExprOpcode::Sub) {
            return None;
        }
        let expression = ir.expressions().get(addend.index())?;
        if expression.opcode() != ECodeExprOpcode::Constant {
            return None;
        }
        let width = expression.width();
        let value = expression.immediate();
        if width == 0 || width > 64 || value >> (width - 1) & 1 == 0 {
            return None;
        }
        let magnitude = if width == 64 {
            value.wrapping_neg()
        } else {
            (1u64 << width) - value
        };
        Some(magnitude)
    }

    fn expr_bytes(&self, ir: &ECodeIr, id: IlExprId) -> u16 {
        ir.expressions()
            .get(id.index())
            .map(|expression| (expression.width() / 8) as u16)
            .unwrap_or(0)
    }

    fn ecode_expr(&self, ir: &ECodeIr, id: IlExprId, out: &mut Vec<IlToken>, parent_prec: u8) {
        let Some(expression) = ir.expressions().get(id.index()) else {
            out.push(IlToken::new(IlTokenKind::Meta, "?"));
            return;
        };
        let operands = ir.expression_operands_for(expression);

        match expression.opcode() {
            ECodeExprOpcode::Constant => out.push(Self::number(expression.immediate())),
            ECodeExprOpcode::Address => out.push(self.address_token(expression.immediate())),
            ECodeExprOpcode::ReadRegister => {
                out.push(self.register(expression.immediate(), expression.width().div_ceil(8)))
            }
            ECodeExprOpcode::ReadFlag => out.push(self.flag(expression.immediate())),
            ECodeExprOpcode::Copy => {
                self.ecode_expr(ir, operands[0], out, parent_prec);
                return;
            }
            ECodeExprOpcode::Undefined => {
                out.push(Self::keyword("undef"));
            }
            ECodeExprOpcode::Load => {
                if let Some(space) = expression.address_space() {
                    out.push(self.space(space));
                }
                out.push(Self::punct("["));
                self.ecode_operand(ir, operands.first().copied(), out);
                out.push(Self::punct("]"));
            }
            opcode => {
                if let Some(symbol) = infix_symbol(opcode) {
                    let precedence = infix_precedence(opcode);
                    let wrap = precedence < parent_prec;
                    if wrap {
                        out.push(Self::punct("("));
                    }
                    self.ecode_expr(ir, operands[0], out, precedence);
                    match self.negated_addend(ir, opcode, operands[1]) {
                        Some(magnitude) => {
                            let flipped = if opcode == ECodeExprOpcode::Add {
                                "-"
                            } else {
                                "+"
                            };
                            out.push(IlToken::new(
                                IlTokenKind::Punctuation,
                                format!(" {flipped} "),
                            ));
                            out.push(Self::number(magnitude));
                        }
                        None => {
                            out.push(IlToken::new(
                                IlTokenKind::Punctuation,
                                format!(" {symbol} "),
                            ));
                            self.ecode_expr(ir, operands[1], out, precedence + 1);
                        }
                    }
                    if wrap {
                        out.push(Self::punct(")"));
                    }
                } else {
                    out.push(Self::opcode(expression.opcode().mnemonic()));
                    if opcode == ECodeExprOpcode::IntrinsicResult {
                        out.push(self.intrinsic_meta(expression.immediate()));
                    }
                    self.ecode_args(ir, operands, out);
                    if matches!(opcode, ECodeExprOpcode::Extract | ECodeExprOpcode::Insert) {
                        out.push(Self::offset_meta(expression.immediate()));
                    }
                }
            }
        }

        if matches!(
            expression.opcode(),
            ECodeExprOpcode::Constant | ECodeExprOpcode::ReadRegister | ECodeExprOpcode::ReadFlag
        ) && let Some(token) = out.last_mut()
        {
            token.title = Some(format!("{} bits", expression.width()));
        }
    }

    pub fn pcode(&self, ir: &PCodeIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for span in ir.source_spans() {
            let range = span.destination();
            for index in range.start()..range.end() {
                let Some(operation) = ir.operations().get(index) else {
                    continue;
                };
                let mut tokens = Vec::new();
                self.pcode_operation(ir, operation, &mut tokens);
                lines.push(IlLine {
                    address: BindingAddress::from(span.address()),
                    tokens,
                });
            }
        }
        lines
    }

    fn pcode_operation(&self, ir: &PCodeIr, operation: &PCodeOp, out: &mut Vec<IlToken>) {
        if let Some(output) = operation.output() {
            self.pcode_location(ir, output, out);
            out.push(Self::punct(" = "));
        }
        out.push(Self::opcode(operation.opcode().mnemonic()));

        for (index, operand) in ir.operation_operands_for(operation).iter().enumerate() {
            out.push(Self::punct(if index == 0 { " " } else { ", " }));
            self.pcode_location(ir, *operand, out);
        }

        if let Some(space) = operation.address_space() {
            out.push(Self::punct(" "));
            out.push(self.space(space));
        }

        if operation.opcode().requires_address()
            && let Some(target) = ir.target(operation.immediate())
        {
            out.push(Self::punct(" -> "));
            out.push(
                IlToken::new(
                    IlTokenKind::Address,
                    format!("{:#x}", target.address().offset()),
                )
                .with_nav(target.address()),
            );
        }
    }

    fn pcode_location(&self, ir: &PCodeIr, id: PCodeLocationId, out: &mut Vec<IlToken>) {
        let Some(location) = ir.location(id) else {
            out.push(IlToken::new(IlTokenKind::Meta, "?"));
            return;
        };
        let bytes = location.size();
        if location.is_constant() {
            out.push(Self::number(location.offset()).with_title(format!("{bytes} bytes")));
        } else if location.is_register() {
            out.push(self.register(location.offset(), u32::from(bytes)));
        } else if location.is_unique() {
            out.push(
                IlToken::new(IlTokenKind::Value, format!("u{:x}", location.offset()))
                    .with_title(format!("unique temporary, {bytes} bytes")),
            );
        } else {
            let name = self
                .lifter
                .space_name(location.lifter_space().value())
                .unwrap_or("mem");
            out.push(IlToken::new(IlTokenKind::Space, name.to_owned()));
            out.push(Self::punct("["));
            out.push(Self::number(location.offset()));
            out.push(Self::punct("]"));
        }
    }

    pub fn ssa(&self, ir: &ECodeSsaIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for address in self.ordered_addresses(ir.source_spans()) {
            for (_, operation) in ir.operations_for_source(address) {
                let mut tokens = Vec::new();
                self.ssa_operation(ir, operation, &mut tokens);
                lines.push(IlLine {
                    address: BindingAddress::from(address),
                    tokens,
                });
            }
        }
        lines
    }

    fn ssa_value(&self, ir: &ECodeSsaIr, id: IlValueId) -> IlToken {
        let token = IlToken::new(IlTokenKind::Value, format!("%v{}", id.index()));
        match ir.values().get(id.index()) {
            Some(value) if value.width() == 0 => token.with_title(self.memory_state_title(ir, id)),
            Some(value) => token.with_title(self.bound_value_title(ir, id, value.width())),
            None => token,
        }
    }

    fn bound_value_title(&self, ir: &ECodeSsaIr, id: IlValueId, width: u32) -> String {
        match ir.value_domain(id) {
            Some(ECodeSsaDomain::Register(offset)) => {
                let name = u16::try_from(width.div_ceil(8).max(1))
                    .ok()
                    .and_then(|bytes| {
                        let varnode = Varnode::new(self.register_space, offset.value(), bytes);
                        self.lifter.register_name(&varnode)
                    });
                match name {
                    Some(name) => format!("{name}, {width} bits"),
                    None => format!("register offset {:#x}, {width} bits", offset.value()),
                }
            }
            Some(ECodeSsaDomain::Flag(offset)) => match self.flags.get(&offset.value()) {
                Some(name) => format!("{name}, {width} bits"),
                None => format!("flag offset {:#x}, {width} bits", offset.value()),
            },
            _ => format!("{width} bits"),
        }
    }

    fn memory_state_title(&self, ir: &ECodeSsaIr, id: IlValueId) -> String {
        let space = ir
            .defining_operation(id)
            .and_then(|operation| match operation.opcode() {
                ECodeSsaOpcode::Undefined => {
                    AddressSpaceId::try_new(operation.immediate() as usize).ok()
                }
                _ => operation.address_space(),
            });
        match space {
            Some(space) => format!("memory state of {}", Self::space_label(space.index())),
            None => "memory state".to_owned(),
        }
    }

    fn undefined_origin(&self, operation: &ECodeSsaOp) -> IlToken {
        if operation.width() == 0 {
            return IlToken::new(
                IlTokenKind::Space,
                Self::space_label(operation.immediate() as usize),
            )
            .with_title("initial memory state");
        }
        let offset = operation.immediate();
        if let Some(name) = self.flags.get(&offset) {
            return IlToken::new(IlTokenKind::Flag, *name).with_title("undefined initial value");
        }
        let bytes = (operation.width() / 8) as u16;
        let varnode = Varnode::new(self.register_space, offset, bytes.max(1));
        match self.lifter.register_name(&varnode) {
            Some(name) => {
                IlToken::new(IlTokenKind::Register, name).with_title("undefined initial value")
            }
            None => IlToken::new(IlTokenKind::Meta, format!("origin<{offset}>")),
        }
    }

    fn ssa_operation(&self, ir: &ECodeSsaIr, operation: &ECodeSsaOp, out: &mut Vec<IlToken>) {
        let results = operation.results();
        for index in results.start()..results.end() {
            if let Ok(id) = IlValueId::try_from_index(index) {
                if index != results.start() {
                    out.push(Self::punct(", "));
                }
                out.push(self.ssa_value(ir, id));
            }
        }
        if !results.is_empty() {
            out.push(Self::punct(" = "));
        }

        out.push(Self::opcode(operation.opcode().mnemonic()));

        match operation.opcode() {
            ECodeSsaOpcode::Constant => {
                out.push(Self::punct(" "));
                out.push(Self::number(operation.immediate()));
            }
            ECodeSsaOpcode::Address => {
                out.push(Self::punct(" "));
                out.push(self.address_token(operation.immediate()));
            }
            ECodeSsaOpcode::Undefined => {
                out.push(Self::punct(" "));
                out.push(self.undefined_origin(operation));
            }
            ECodeSsaOpcode::Intrinsic | ECodeSsaOpcode::IntrinsicResult => {
                out.push(self.intrinsic_meta(operation.immediate()));
            }
            ECodeSsaOpcode::WriteFlag => {
                out.push(Self::punct(" "));
                out.push(self.flag(operation.immediate()));
            }
            ECodeSsaOpcode::WriteRegister => {
                out.push(Self::punct(" "));
                out.push(self.register(operation.immediate(), operation.width().div_ceil(8)));
            }
            _ => {}
        }

        for operand in ir.operation_operands_for(operation) {
            out.push(Self::punct(" "));
            out.push(self.ssa_value(ir, *operand));
        }

        if matches!(
            operation.opcode(),
            ECodeSsaOpcode::Extract | ECodeSsaOpcode::Insert
        ) {
            out.push(Self::punct(" "));
            out.push(Self::offset_meta(operation.immediate()));
        }

        if let Some(space) = operation.address_space() {
            out.push(Self::punct(" "));
            out.push(self.space(space));
        }

        if let Some(address) = operation.address() {
            out.push(Self::punct(" -> "));
            out.push(
                IlToken::new(IlTokenKind::Address, format!("{:#x}", address.offset()))
                    .with_nav(address),
            );
        }
    }

    pub fn mcode_ssa(&self, ir: &MCodeSsaIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for address in self.ordered_addresses(ir.source_spans()) {
            for (_, operation) in ir.operations_for_source(address) {
                let mut tokens = Vec::new();
                self.mcode_ssa_operation(ir, operation, &mut tokens);
                lines.push(IlLine {
                    address: BindingAddress::from(address),
                    tokens,
                });
            }
        }
        lines
    }

    fn mcode_ssa_value(&self, ir: &MCodeSsaIr, id: IlValueId) -> IlToken {
        let Some(value) = ir.values().get(id.index()) else {
            return IlToken::new(IlTokenKind::Meta, "?");
        };
        let Some(binding) = ir.binding(id) else {
            let token = IlToken::new(IlTokenKind::Value, format!("%v{}", id.index()));
            return if value.width() == 0 {
                token.with_title(self.mcode_memory_state_title(ir, id))
            } else {
                token.with_title(format!("{} bits", value.width()))
            };
        };
        self.mcode_variable(
            ir,
            binding.variable(),
            Some(binding.version().value()),
            value.width(),
        )
    }

    fn mcode_variable(
        &self,
        ir: &MCodeSsaIr,
        id: MCodeVarId,
        version: Option<u32>,
        width: u32,
    ) -> IlToken {
        let Some(variable) = ir.variable(id) else {
            let version = version
                .map(|version| format!("#{version}"))
                .unwrap_or_default();
            return IlToken::new(IlTokenKind::Meta, format!("var<?>{version}"));
        };
        let lifetime = (variable.index() != 0).then(|| format!("_{}", variable.index()));
        let version = version
            .map(|version| format!("#{version}"))
            .unwrap_or_default();
        match variable.kind() {
            MCodeVarKind::Flag => {
                let storage = variable
                    .flag_id()
                    .expect("flag variable has flag storage")
                    .value();
                let mut token = self.flag(storage);
                if let Some(lifetime) = lifetime {
                    token.text.push_str(&lifetime);
                }
                token.text.push_str(&version);
                token.with_title(format!("flag storage {storage:#x}, {width} bits"))
            }
            MCodeVarKind::Register => {
                let storage = variable
                    .register_id()
                    .expect("register variable has register storage")
                    .value();
                let mut token = self.register(storage, width.div_ceil(8));
                if let Some(lifetime) = lifetime {
                    token.text.push_str(&lifetime);
                }
                token.text.push_str(&version);
                token.with_title(format!("register storage {storage:#x}, {width} bits"))
            }
            MCodeVarKind::Stack => {
                let storage = variable
                    .stack_offset()
                    .expect("stack variable has stack storage");
                let lifetime = lifetime.unwrap_or_default();
                IlToken::new(
                    IlTokenKind::Value,
                    format!("stack[{storage:#x}]{lifetime}{version}"),
                )
                .with_title(format!("stack storage {storage:#x}, {width} bits"))
            }
        }
    }

    fn mcode_memory_state_title(&self, ir: &MCodeSsaIr, id: IlValueId) -> String {
        let space = ir
            .defining_operation(id)
            .and_then(|operation| match operation.opcode() {
                MCodeSsaOpcode::Undefined => {
                    AddressSpaceId::try_new(operation.immediate() as usize).ok()
                }
                _ => operation.address_space(),
            });
        match space {
            Some(space) => format!("memory state of {}", Self::space_label(space.index())),
            None => "memory state".to_owned(),
        }
    }

    fn mcode_ssa_operation(&self, ir: &MCodeSsaIr, operation: &MCodeSsaOp, out: &mut Vec<IlToken>) {
        let results = operation.results();
        for index in results.start()..results.end() {
            if let Ok(id) = IlValueId::try_from_index(index) {
                if index != results.start() {
                    out.push(Self::punct(", "));
                }
                out.push(self.mcode_ssa_value(ir, id));
            }
        }
        if !results.is_empty() {
            out.push(Self::punct(" = "));
        }
        out.push(Self::opcode(operation.opcode().mnemonic()));

        match operation.opcode() {
            MCodeSsaOpcode::Constant if operation.width() > 64 => {
                if let Some(value) = IlValueId::try_from_index(results.start())
                    .ok()
                    .and_then(|value| ir.constant_value(value))
                {
                    out.push(Self::punct(" "));
                    out.push(IlToken::new(IlTokenKind::Number, format!("0x{value:x}")));
                }
            }
            MCodeSsaOpcode::Constant => {
                out.push(Self::punct(" "));
                out.push(Self::number(operation.immediate()));
            }
            MCodeSsaOpcode::Address => {
                out.push(Self::punct(" "));
                out.push(self.address_token(operation.immediate()));
            }
            MCodeSsaOpcode::Intrinsic | MCodeSsaOpcode::IntrinsicResult => {
                out.push(self.intrinsic_meta(operation.immediate()));
            }
            MCodeSsaOpcode::SetVarField
            | MCodeSsaOpcode::VarAliasedField
            | MCodeSsaOpcode::SetVarAliasedField
            | MCodeSsaOpcode::AddressOfField => {
                out.push(Self::punct(" "));
                out.push(Self::offset_meta(operation.immediate()));
            }
            _ => {}
        }

        if matches!(
            operation.opcode(),
            MCodeSsaOpcode::VarAliased
                | MCodeSsaOpcode::VarAliasedField
                | MCodeSsaOpcode::AddressOf
                | MCodeSsaOpcode::AddressOfField
        ) && let Some(variable) = operation.variable()
        {
            out.push(Self::punct(" "));
            out.push(self.mcode_variable(ir, variable, None, operation.width()));
        }
        for operand in ir.operation_operands_for(operation) {
            out.push(Self::punct(" "));
            out.push(self.mcode_ssa_value(ir, *operand));
        }
        if let Some(space) = operation.address_space() {
            out.push(Self::punct(" "));
            out.push(self.space(space));
        }
        if let Some(address) = operation.address() {
            out.push(Self::punct(" -> "));
            out.push(
                IlToken::new(IlTokenKind::Address, format!("{:#x}", address.offset()))
                    .with_nav(address),
            );
        }
    }
}

fn infix_symbol(opcode: ECodeExprOpcode) -> Option<&'static str> {
    Some(match opcode {
        ECodeExprOpcode::Add => "+",
        ECodeExprOpcode::Sub => "-",
        ECodeExprOpcode::Mul => "*",
        ECodeExprOpcode::And => "&",
        ECodeExprOpcode::Or => "|",
        ECodeExprOpcode::Xor => "^",
        ECodeExprOpcode::LeftShift => "<<",
        ECodeExprOpcode::LogicalRightShift => ">>",
        _ => return None,
    })
}

fn infix_precedence(opcode: ECodeExprOpcode) -> u8 {
    match opcode {
        ECodeExprOpcode::Mul => 4,
        ECodeExprOpcode::LeftShift | ECodeExprOpcode::LogicalRightShift => 3,
        ECodeExprOpcode::Add | ECodeExprOpcode::Sub => 2,
        _ => PREC_INFIX_MIN,
    }
}
