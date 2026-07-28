use crate::ir::symbol::{Symbol, SymbolSet};
use crate::platform::OperatingSystem;
use crate::registry::{self, Registration};

type NonReturningExternsFn = fn() -> &'static SymbolSet;

pub struct NonReturningExterns {
    name: &'static str,
    operating_systems: &'static [OperatingSystem],
    externs: NonReturningExternsFn,
}

impl NonReturningExterns {
    pub const fn new(
        name: &'static str,
        operating_systems: &'static [OperatingSystem],
        externs: NonReturningExternsFn,
    ) -> Self {
        Self {
            name,
            operating_systems,
            externs,
        }
    }

    pub fn operating_systems(&self) -> &'static [OperatingSystem] {
        self.operating_systems
    }

    pub fn externs(&self) -> &'static SymbolSet {
        (self.externs)()
    }

    pub fn covers(&self, os: OperatingSystem) -> bool {
        self.operating_systems.contains(&os)
    }
}

impl Registration for NonReturningExterns {
    fn name(&self) -> &'static str {
        self.name
    }
}

registry::collect!(NonReturningExterns);

pub fn is_non_returning_extern(os: OperatingSystem, symbol: Symbol) -> bool {
    registry::iter::<NonReturningExterns>()
        .filter(|registration| registration.covers(os))
        .any(|registration| registration.externs().contains(&symbol))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::symbol::symbol;

    #[test]
    fn test_non_returning_externs_are_selected_by_operating_system() {
        let linux = |name| is_non_returning_extern(OperatingSystem::Linux, symbol(name));
        let windows = |name| is_non_returning_extern(OperatingSystem::Windows, symbol(name));

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

        assert!(!is_non_returning_extern(
            OperatingSystem::Unknown,
            symbol("abort")
        ));
    }
}
