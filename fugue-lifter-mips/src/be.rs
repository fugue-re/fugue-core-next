use fugue_lifter_runtime::{Language, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/mips_be.rs"));
}
pub use __impl::{LANGUAGE, context, register, space, user_op};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        Lifter::new(&__impl::LANGUAGE)
    }

    pub fn language(&self) -> &'static Language {
        &__impl::LANGUAGE
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: &Language = &__impl::LANGUAGE;
}
