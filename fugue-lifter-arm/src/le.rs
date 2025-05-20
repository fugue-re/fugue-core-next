use fugue_lifter_runtime::{Language, LanguageVariant, Lifter, LiftingContext};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/arm_le.rs"));
}
pub use __impl::{context, register, space, user_op, LANGUAGE};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_v8() -> Lifter {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 0);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        Lifter::new(&__impl::LANGUAGE, __impl::lifter_with(2, base))
    }

    pub fn new_v8t() -> Lifter {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 1);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        Lifter::new(&__impl::LANGUAGE, __impl::lifter_with(2, base))
    }

    pub fn language(&self) -> &'static Language {
        &__impl::LANGUAGE
    }
}

pub struct LiftingContextFactory;

impl LiftingContextFactory {
    pub fn new() -> LiftingContext {
        Self::new_v8()
    }

    pub fn new_v8() -> LiftingContext {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 0);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        __impl::lifter_with(2, base)
    }

    pub fn new_v8t() -> LiftingContext {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 1);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        __impl::lifter_with(2, base)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = V8;
    pub const DEFAULT_THUMB: LanguageVariant = V8T;

    pub const V8: LanguageVariant =
        LanguageVariant::new("v8", LANGUAGE, LiftingContextFactory::new_v8);
    pub const V8T: LanguageVariant =
        LanguageVariant::new("v8T", LANGUAGE, LiftingContextFactory::new_v8t);
}
