use fugue_lifter_runtime::{Language, LanguageVariant, Lifter, LiftingContext};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/mips_le.rs"));
}
pub use __impl::{context, register, space, user_op, LANGUAGE};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        Lifter::new(
            &__impl::LANGUAGE,
            __impl::lifter_with(&__impl::LANGUAGE, 2, __impl::default_context()),
        )
    }

    pub fn language(&self) -> &'static Language {
        &__impl::LANGUAGE
    }
}

pub struct LiftingContextFactory;

impl LiftingContextFactory {
    pub fn new() -> LiftingContext {
        Self::new_default()
    }

    pub fn new_default() -> LiftingContext {
        __impl::lifter_with(&__impl::LANGUAGE, 2, __impl::default_context())
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = MIPS32;
    pub const MIPS32: LanguageVariant =
        LanguageVariant::new("default", &__impl::LANGUAGE, LiftingContextFactory::new_default);
}
