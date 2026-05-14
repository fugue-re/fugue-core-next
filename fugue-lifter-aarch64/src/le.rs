use fugue_lifter_runtime::{Language, LanguageVariant, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/aarch64_le.rs"));
}
pub use __impl::{context, register, space, user_op, LANGUAGE};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_v8a() -> Lifter {
        Lifter::new(&__impl::LANGUAGE)
    }

    pub fn language(&self) -> &'static Language {
        &__impl::LANGUAGE
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = V8A;
    pub const V8A: LanguageVariant = LanguageVariant::new("v8A", &__impl::LANGUAGE);
}
