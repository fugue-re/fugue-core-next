use crate::ir::{ExternSymbols, LocalSymbols};

pub trait FunctionTable {}

pub trait SymbolTable {
    fn local(&self) -> Option<&LocalSymbols>;
    fn external(&self) -> Option<&ExternSymbols>;
}
