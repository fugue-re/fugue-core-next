use crate::context::{ContextBitRange, ContextPostAction, ContextPreAction};
use crate::operand::Operand;
use crate::pattern::PatternOp;
use crate::pcode::Varnode;
use crate::template::{ConstTpl, HandleTpl, VarnodeTpl};

pub(crate) trait Install {
    type Target: 'static;

    fn install(self) -> Self::Target;
}

impl Install for Box<str> {
    type Target = &'static str;

    fn install(self) -> Self::Target {
        Box::leak(self)
    }
}

impl<T: Install> Install for Option<T> {
    type Target = Option<T::Target>;

    fn install(self) -> Self::Target {
        self.map(T::install)
    }
}

impl<T: Install> Install for Box<[T]> {
    type Target = &'static [T::Target];

    fn install(self) -> Self::Target {
        let mapped = Vec::from(self)
            .into_iter()
            .map(T::install)
            .collect::<Box<[T::Target]>>();
        Box::leak(mapped)
    }
}

impl<A: Install, B: Install> Install for (A, B) {
    type Target = (A::Target, B::Target);

    fn install(self) -> Self::Target {
        (self.0.install(), self.1.install())
    }
}

impl<A: Install, B: Install, C: Install> Install for (A, B, C) {
    type Target = (A::Target, B::Target, C::Target);

    fn install(self) -> Self::Target {
        (self.0.install(), self.1.install(), self.2.install())
    }
}

macro_rules! install_identity {
    ($($t:ty),* $(,)?) => {
        $(
            impl Install for $t {
                type Target = $t;

                fn install(self) -> Self::Target {
                    self
                }
            }
        )*
    };
}

install_identity!(
    u16,
    u32,
    u64,
    i64,
    usize,
    Varnode,
    ContextBitRange,
    ContextPreAction,
    ContextPostAction,
    Operand,
    PatternOp,
    ConstTpl,
    HandleTpl,
    VarnodeTpl,
);
