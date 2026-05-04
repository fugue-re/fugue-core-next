use fugue_lifter_runtime::{Language, LanguageVariant, Lifter, LiftingContext};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/aarch64_be.rs"));
}
pub use __impl::{context, register, space, user_op, LANGUAGE};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_v8a() -> Lifter {
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
        Self::new_v8a()
    }

    pub fn new_v8a() -> LiftingContext {
        __impl::lifter_with(&__impl::LANGUAGE, 2, __impl::default_context())
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = V8A;
    pub const V8A: LanguageVariant =
        LanguageVariant::new("v8A", &__impl::LANGUAGE, LiftingContextFactory::new_v8a);
}
