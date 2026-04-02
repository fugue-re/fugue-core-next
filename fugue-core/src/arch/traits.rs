use std::borrow::Borrow;

use bitflags::bitflags;
use clone_dyn::clone_dyn;

use crate::il::pcode::Varnode;
use crate::ir::{Endian, ExternFunctionTemplate, Address, Symbol};
use crate::lifter::{
    ContextHint, ContextSet, Disassembler, Language, LanguageVariant, Lifter, LiftingContext,
};

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FlagKind: u8 {
        const Z = 0b0000_0001;
        const C = 0b0000_0010;
        const N = 0b0000_0100;
        const V = 0b0000_1000;
        const P = 0b0001_0000;
        const A = 0b0010_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Flag {
    var: Varnode,
    kind: FlagKind,
}

impl Borrow<Varnode> for Flag {
    fn borrow(&self) -> &Varnode {
        &self.var
    }
}

impl PartialEq<&'_ Varnode> for Flag {
    fn eq(&self, other: &&'_ Varnode) -> bool {
        self.var == **other
    }
}

impl PartialEq<Varnode> for Flag {
    fn eq(&self, other: &Varnode) -> bool {
        self.var == *other
    }
}

impl Flag {
    pub const fn new(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::empty())
    }

    pub const fn new_with(var: Varnode, kind: FlagKind) -> Self {
        Self { var, kind }
    }

    pub const fn z(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::Z)
    }

    pub const fn c(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::C)
    }

    pub const fn n(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::N)
    }

    pub const fn v(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::V)
    }

    pub const fn p(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::P)
    }

    pub const fn a(var: Varnode) -> Self {
        Self::new_with(var, FlagKind::A)
    }

    pub fn kind(&self) -> FlagKind {
        self.kind
    }

    pub fn variable(&self) -> Varnode {
        self.var
    }
}

#[clone_dyn]
pub trait Arch: Send + Sync + 'static {
    fn dissassembler(&self) -> Disassembler;

    fn lifter(&self) -> Lifter;

    fn endian(&self) -> Endian {
        if self.language().is_little_endian() {
            Endian::Little
        } else {
            Endian::Big
        }
    }

    fn canonicalise_address(&self, addr: Address) -> Option<(Address, ContextSet)> {
        let naddr = addr.wrap(self.language()).align(self.language().address_alignment());
        (naddr == addr).then(|| (naddr, ContextSet::new()))
    }

    // NOTE: we the lifting context associated should be tied to the address space the address
    // belongs to.
    fn canonicalise_address_with(
        &self,
        addr: Address,
        context: &LiftingContext,
    ) -> Option<(Address, ContextSet)> {
        let _ = context;
        self.canonicalise_address(addr)
    }

    fn external_function_template(&self) -> ExternFunctionTemplate;

    fn flags(&self) -> &[Flag] {
        &[]
    }

    fn frame_pointer(&self) -> Option<Varnode> {
        None
    }

    fn gprs(&self) -> &[Varnode] {
        &[]
    }

    #[allow(unused)]
    fn is_halt_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_nonsense_pattern(&self, bytes: &[u8]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_service_call(&self, op: u16, args: &[Varnode]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_skip_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        false
    }

    #[allow(unused)]
    fn is_trap_intrinsic(&self, op: u16, args: &[Varnode]) -> bool {
        false
    }

    #[allow(unused)]
    fn resolve_mapping_symbol(&self, symbol: &Symbol) -> Option<ContextHint> {
        None
    }

    fn language(&self) -> &'static Language {
        self.language_variant().language()
    }

    fn language_variant(&self) -> LanguageVariant;
}
