use fugue_lifter_runtime::{LanguageVariant, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/x86.rs"));
}

pub use __impl::{context, register, space, user_op, LANGUAGE};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        Lifter::new(&__impl::LANGUAGE)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = LanguageVariant::new("default", &__impl::LANGUAGE);
}
