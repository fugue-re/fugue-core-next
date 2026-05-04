use fugue_lifter_runtime::{LanguageVariant, Lifter, LiftingContext};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/x86.rs"));
}

pub use __impl::{context, register, space, user_op, LANGUAGE};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::ADDRSIZE, 1);
        base.set_variable_default_by_bits(context::OPSIZE, 1);

        Lifter::new(
            &__impl::LANGUAGE,
            __impl::lifter_with(&__impl::LANGUAGE, 2, base),
        )
    }
}

pub struct LiftingContextFactory;

impl LiftingContextFactory {
    pub fn new() -> LiftingContext {
        Self::new_default()
    }

    pub fn new_default() -> LiftingContext {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::ADDRSIZE, 1);
        base.set_variable_default_by_bits(context::OPSIZE, 1);

        __impl::lifter_with(&__impl::LANGUAGE, 2, base)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant =
        LanguageVariant::new("default", &__impl::LANGUAGE, LiftingContextFactory::new_default);
}
