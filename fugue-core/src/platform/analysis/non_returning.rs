use crate::extension::{self, Registration};
use crate::ir::symbol::{Symbol, SymbolSet, existing_symbol};
use crate::platform::Platform;

type NonReturningExternalSetFn = fn() -> &'static SymbolSet;
type NonReturningExternalSetSupportsFn = fn(&Platform) -> bool;
type NonReturningExternalSetSymbolNameFn = fn(&str) -> &str;

pub struct NonReturningExternalSet {
    name: &'static str,
    supports: NonReturningExternalSetSupportsFn,
    externals: NonReturningExternalSetFn,
    symbol_name: NonReturningExternalSetSymbolNameFn,
}

impl NonReturningExternalSet {
    pub const fn new(
        name: &'static str,
        supports: NonReturningExternalSetSupportsFn,
        externals: NonReturningExternalSetFn,
        symbol_name: NonReturningExternalSetSymbolNameFn,
    ) -> Self {
        Self {
            name,
            supports,
            externals,
            symbol_name,
        }
    }

    pub fn supports(&self, platform: &Platform) -> bool {
        (self.supports)(platform)
    }

    pub fn externals(&self) -> &'static SymbolSet {
        (self.externals)()
    }

    pub fn contains(&self, symbol: Symbol) -> bool {
        existing_symbol((self.symbol_name)(&symbol))
            .is_some_and(|symbol| self.externals().contains(&symbol))
    }
}

impl Registration for NonReturningExternalSet {
    fn name(&self) -> &'static str {
        self.name
    }
}

extension::collect!(NonReturningExternalSet);

pub fn is_non_returning_external(platform: &Platform, symbol: Symbol) -> bool {
    extension::iter::<NonReturningExternalSet>()
        .filter(|registration| registration.supports(platform))
        .any(|registration| registration.contains(symbol))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::Endian;
    use crate::ir::symbol::symbol;
    use crate::platform::{OperatingSystem, TypeLayout};

    #[test]
    fn test_non_returning_externs_are_selected_by_operating_system() {
        let platform = |os| Platform::new(TypeLayout::new(8, Endian::Little)).with_os(os);
        let linux_platform = platform(OperatingSystem::Linux);
        let windows_platform = platform(OperatingSystem::Windows);
        let linux = |name| is_non_returning_external(&linux_platform, symbol(name));
        let windows = |name| is_non_returning_external(&windows_platform, symbol(name));

        assert!(linux("__stack_chk_fail"));
        assert!(linux("_Unwind_Resume"));
        assert!(!linux("ExitProcess"));
        assert!(!linux("_endthreadex"));

        assert!(windows("ExitProcess"));
        assert!(windows("KeBugCheckEx"));
        assert!(!windows("__stack_chk_fail"));
        assert!(!windows("_Unwind_Resume"));

        assert!(!linux("_cexit"));
        assert!(!windows("_cexit"));

        assert!(!is_non_returning_external(
            &platform(OperatingSystem::Unknown),
            symbol("abort")
        ));
    }
}
