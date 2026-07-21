use crate::ir::symbol::{Symbol, symbol};
use crate::registry::{self, Registration};

mod posix;
mod windows;

pub struct NonReturningExterns {
    registration_name: &'static str,
    names: &'static [&'static str],
}

impl NonReturningExterns {
    pub const fn new(registration_name: &'static str, names: &'static [&'static str]) -> Self {
        Self {
            registration_name,
            names,
        }
    }

    pub fn names(&self) -> impl Iterator<Item = Symbol> + '_ {
        self.names.iter().map(|name| symbol(name))
    }
}

impl Registration for NonReturningExterns {
    fn name(&self) -> &'static str {
        self.registration_name
    }
}

registry::collect!(NonReturningExterns);

pub fn non_returning_extern_names() -> impl Iterator<Item = Symbol> {
    registry::iter::<NonReturningExterns>().flat_map(NonReturningExterns::names)
}
