use std::borrow::Borrow;

use fugue_core::arch::Arch;
use fugue_core::il::common::{IlSourceSpan, IlValueId};
use fugue_core::il::ecode::{ECodeDomain, ECodeIr, ECodeOp, ECodeOpcode};
use fugue_core::il::mcode::{MCodeIr, MCodeOp, MCodeOpcode, MCodeVarId, MCodeVarKind};
use fugue_core::il::pcode::{PCodeIr, PCodeLocationId, PCodeOp};
use fugue_core::ir::Address;
use fugue_core::lifter::{Lifter, Varnode};
use fugue_core::storage::{AddressSpaceId, DEFAULT_SPACE_ID};
use rustc_hash::FxHashMap;

use crate::bindings::{Address as BindingAddress, IlLine, IlToken, IlTokenKind};

pub struct IlRenderer {
    lifter: Lifter,
    register_space: u8,
    flags: FxHashMap<u64, &'static str>,
}

fn ordered_addresses(spans: &[IlSourceSpan]) -> Vec<Address> {
    let mut addresses = spans.iter().map(|span| span.address()).collect::<Vec<_>>();
    addresses.sort_by_key(Address::offset);
    addresses.dedup();
    addresses
}

fn opcode(mnemonic: &str) -> IlToken {
    IlToken::new(IlTokenKind::Opcode, mnemonic)
}

fn punct(text: &str) -> IlToken {
    IlToken::new(IlTokenKind::Punctuation, text)
}

fn number(value: u64) -> IlToken {
    IlToken::new(IlTokenKind::Number, format!("{value:#x}"))
}

fn space_label(index: usize) -> String {
    format!("mem<{index}>")
}

fn offset_meta(immediate: u64) -> IlToken {
    IlToken::new(IlTokenKind::Meta, format!("@{immediate}")).with_title("bit offset")
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

    fn space(&self, space: AddressSpaceId) -> IlToken {
        IlToken::new(IlTokenKind::Space, space_label(space.index()))
    }

    fn address_token(&self, offset: u64) -> IlToken {
        IlToken::new(IlTokenKind::Address, format!("{offset:#x}"))
            .with_nav(Address::new(DEFAULT_SPACE_ID, offset))
    }

    pub fn pcode(&self, ir: &PCodeIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for span in ir.source_spans() {
            let range = span.destination();
            for index in range.start()..range.end() {
                let Some(operation) = ir.ops().get(index) else {
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
            out.push(punct(" = "));
        }
        out.push(opcode(operation.opcode().mnemonic()));

        for (index, operand) in ir.op_operands_for(operation).iter().enumerate() {
            out.push(punct(if index == 0 { " " } else { ", " }));
            self.pcode_location(ir, *operand, out);
        }

        if let Some(space) = operation.address_space() {
            out.push(punct(" "));
            out.push(self.space(space));
        }

        if operation.opcode().requires_address()
            && let Some(target) = operation.target().and_then(|target| ir.target(target))
        {
            out.push(punct(" -> "));
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
            out.push(number(location.offset()).with_title(format!("{bytes} bytes")));
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
            out.push(punct("["));
            out.push(number(location.offset()));
            out.push(punct("]"));
        }
    }

    pub fn ecode(&self, ir: &ECodeIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for address in ordered_addresses(ir.source_spans()) {
            for (_, operation) in ir.ops_for_source(address) {
                let mut tokens = Vec::new();
                self.ecode_operation(ir, operation, &mut tokens);
                lines.push(IlLine {
                    address: BindingAddress::from(address),
                    tokens,
                });
            }
        }
        lines
    }

    fn ecode_value(&self, ir: &ECodeIr, id: IlValueId) -> IlToken {
        let token = IlToken::new(IlTokenKind::Value, format!("%v{}", id.index()));
        match ir.values().get(id.index()) {
            Some(value) if value.width() == 0 => token.with_title(self.memory_state_title(ir, id)),
            Some(value) => token.with_title(self.bound_value_title(ir, id, value.width())),
            None => token,
        }
    }

    fn bound_value_title(&self, ir: &ECodeIr, id: IlValueId, width: u32) -> String {
        match ir.value_domain(id) {
            Some(ECodeDomain::Register(offset)) => {
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
            Some(ECodeDomain::Flag(offset)) => match self.flags.get(&offset.value()) {
                Some(name) => format!("{name}, {width} bits"),
                None => format!("flag offset {:#x}, {width} bits", offset.value()),
            },
            _ => format!("{width} bits"),
        }
    }

    fn memory_state_title(&self, ir: &ECodeIr, id: IlValueId) -> String {
        let space = ir
            .defining_op(id)
            .and_then(|operation| match operation.opcode() {
                ECodeOpcode::Undefined => usize::try_from(operation.immediate())
                    .ok()
                    .and_then(|index| AddressSpaceId::try_new(index).ok()),
                _ => operation.address_space(),
            });
        match space {
            Some(space) => format!("memory state of {}", space_label(space.index())),
            None => "memory state".to_owned(),
        }
    }

    fn undefined_origin(&self, ir: &ECodeIr, operation: &ECodeOp) -> IlToken {
        let domain = IlValueId::try_from_index(operation.results().start())
            .ok()
            .and_then(|value| ir.value_domain(value));

        self.undefined_domain(domain, operation.width())
    }

    fn undefined_domain(&self, domain: Option<ECodeDomain>, width: u32) -> IlToken {
        match domain {
            Some(ECodeDomain::Memory(space)) => {
                self.space(space).with_title("initial memory state")
            }
            Some(ECodeDomain::Flag(flag)) => self
                .flag(flag.value())
                .with_title("undefined initial value"),
            Some(ECodeDomain::Register(register)) => self
                .register(register.value(), width.div_ceil(8))
                .with_title("undefined initial value"),
            None => IlToken::new(IlTokenKind::Meta, "origin<?>"),
        }
    }

    fn ecode_operation(&self, ir: &ECodeIr, operation: &ECodeOp, out: &mut Vec<IlToken>) {
        let results = operation.results();
        for index in results.start()..results.end() {
            if let Ok(id) = IlValueId::try_from_index(index) {
                if index != results.start() {
                    out.push(punct(", "));
                }
                out.push(self.ecode_value(ir, id));
            }
        }
        if !results.is_empty() {
            out.push(punct(" = "));
        }

        out.push(opcode(operation.opcode().mnemonic()));

        match operation.opcode() {
            ECodeOpcode::Constant => {
                out.push(punct(" "));
                out.push(number(operation.immediate()));
            }
            ECodeOpcode::Address => {
                out.push(punct(" "));
                out.push(self.address_token(operation.immediate()));
            }
            ECodeOpcode::Undefined => {
                out.push(punct(" "));
                out.push(self.undefined_origin(ir, operation));
            }
            ECodeOpcode::Intrinsic | ECodeOpcode::IntrinsicResult => {
                out.push(self.intrinsic_meta(operation.immediate()));
            }
            ECodeOpcode::WriteFlag => {
                out.push(punct(" "));
                out.push(self.flag(operation.immediate()));
            }
            ECodeOpcode::WriteRegister => {
                out.push(punct(" "));
                out.push(self.register(operation.immediate(), operation.width().div_ceil(8)));
            }
            _ => {}
        }

        for operand in ir.op_operands_for(operation) {
            out.push(punct(" "));
            out.push(self.ecode_value(ir, *operand));
        }

        if matches!(
            operation.opcode(),
            ECodeOpcode::Extract | ECodeOpcode::Insert
        ) {
            out.push(punct(" "));
            out.push(offset_meta(operation.immediate()));
        }

        if let Some(space) = operation.address_space() {
            out.push(punct(" "));
            out.push(self.space(space));
        }

        if let Some(address) = operation.address() {
            out.push(punct(" -> "));
            out.push(
                IlToken::new(IlTokenKind::Address, format!("{:#x}", address.offset()))
                    .with_nav(address),
            );
        }
    }

    pub fn mcode(&self, ir: &MCodeIr) -> Vec<IlLine> {
        let mut lines = Vec::new();
        for address in ordered_addresses(ir.source_spans()) {
            for (_, operation) in ir.ops_for_source(address) {
                let mut tokens = Vec::new();
                self.mcode_operation(ir, operation, &mut tokens);
                lines.push(IlLine {
                    address: BindingAddress::from(address),
                    tokens,
                });
            }
        }
        lines
    }

    fn mcode_value(&self, ir: &MCodeIr, id: IlValueId) -> IlToken {
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
        ir: &MCodeIr,
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

    fn mcode_memory_state_title(&self, ir: &MCodeIr, id: IlValueId) -> String {
        let space = ir
            .defining_op(id)
            .and_then(|operation| match operation.opcode() {
                MCodeOpcode::Undefined => usize::try_from(operation.immediate())
                    .ok()
                    .and_then(|index| AddressSpaceId::try_new(index).ok()),
                _ => operation.address_space(),
            });
        match space {
            Some(space) => format!("memory state of {}", space_label(space.index())),
            None => "memory state".to_owned(),
        }
    }

    fn mcode_operation(&self, ir: &MCodeIr, operation: &MCodeOp, out: &mut Vec<IlToken>) {
        let results = operation.results();
        for index in results.start()..results.end() {
            if let Ok(id) = IlValueId::try_from_index(index) {
                if index != results.start() {
                    out.push(punct(", "));
                }
                out.push(self.mcode_value(ir, id));
            }
        }
        if !results.is_empty() {
            out.push(punct(" = "));
        }
        out.push(opcode(operation.opcode().mnemonic()));

        match operation.opcode() {
            MCodeOpcode::Constant if operation.width() > 64 => {
                if let Some(value) = IlValueId::try_from_index(results.start())
                    .ok()
                    .and_then(|value| ir.constant_value(value))
                {
                    out.push(punct(" "));
                    out.push(IlToken::new(IlTokenKind::Number, format!("0x{value:x}")));
                }
            }
            MCodeOpcode::Constant => {
                out.push(punct(" "));
                out.push(number(operation.immediate()));
            }
            MCodeOpcode::Address => {
                out.push(punct(" "));
                out.push(self.address_token(operation.immediate()));
            }
            MCodeOpcode::Intrinsic | MCodeOpcode::IntrinsicResult => {
                out.push(self.intrinsic_meta(operation.immediate()));
            }
            MCodeOpcode::SetVarField
            | MCodeOpcode::VarAliasedField
            | MCodeOpcode::SetVarAliasedField
            | MCodeOpcode::AddressOfField => {
                out.push(punct(" "));
                out.push(offset_meta(operation.immediate()));
            }
            _ => {}
        }

        if matches!(
            operation.opcode(),
            MCodeOpcode::VarAliased
                | MCodeOpcode::VarAliasedField
                | MCodeOpcode::AddressOf
                | MCodeOpcode::AddressOfField
        ) && let Some(variable) = operation.variable()
        {
            out.push(punct(" "));
            out.push(self.mcode_variable(ir, variable, None, operation.width()));
        }
        for operand in ir.op_operands_for(operation) {
            out.push(punct(" "));
            out.push(self.mcode_value(ir, *operand));
        }
        if let Some(space) = operation.address_space() {
            out.push(punct(" "));
            out.push(self.space(space));
        }
        if let Some(address) = operation.address() {
            out.push(punct(" -> "));
            out.push(
                IlToken::new(IlTokenKind::Address, format!("{:#x}", address.offset()))
                    .with_nav(address),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use fugue_core::il::common::{FlagId, RegisterId};
    use fugue_core::loader::Loader;
    use fugue_core::project::Project;

    use super::*;

    fn renderer() -> IlRenderer {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fugue-core/tests/ls.elf");
        let loader = Loader::from_file(fixture).expect("the fixture loads");
        let project = Project::new_transient(&loader).expect("the project opens");

        IlRenderer::new(project.arch())
    }

    #[test]
    fn undefined_domains_do_not_guess_from_colliding_identifiers() {
        let renderer = renderer();
        let offset = renderer
            .flags
            .keys()
            .next()
            .copied()
            .expect("the fixture architecture defines a flag");

        let flag = renderer.undefined_domain(Some(ECodeDomain::Flag(FlagId::new(offset))), 1);
        let register =
            renderer.undefined_domain(Some(ECodeDomain::Register(RegisterId::new(offset))), 8);

        assert_eq!(flag.kind, IlTokenKind::Flag);
        assert_eq!(register.kind, IlTokenKind::Register);
    }

    #[test]
    fn undefined_register_width_rounds_up_to_whole_bytes() {
        let renderer = renderer();
        let offset = 0;
        let expected = Varnode::new(renderer.register_space, offset, 2);
        let expected = renderer
            .lifter
            .register_name(&expected)
            .expect("the fixture architecture has a two-byte root slice");

        let register =
            renderer.undefined_domain(Some(ECodeDomain::Register(RegisterId::new(offset))), 9);

        assert_eq!(register.kind, IlTokenKind::Register);
        assert_eq!(register.text, expected);
    }
}
