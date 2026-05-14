use fugue_lifter_runtime::{LanguageVariant, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/x86_64.rs"));
}

pub use __impl::{context, register, space, user_op, LANGUAGE_COMPAT32, LANGUAGE_DEFAULT};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_DEFAULT)
    }

    pub fn new_compat32() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_COMPAT32)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant =
        LanguageVariant::new("default", &__impl::LANGUAGE_DEFAULT);
    pub const COMPAT32: LanguageVariant =
        LanguageVariant::new("compat32", &__impl::LANGUAGE_COMPAT32);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn variant_tag_matches_factory() {
        assert_eq!(LifterFactory::new_default().language().variant(), "default");
        assert_eq!(LifterFactory::new_compat32().language().variant(), "compat32");
    }
}
