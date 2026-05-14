use fugue_lifter_runtime::{Language, LanguageVariant, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/arm_le.rs"));
}
pub use __impl::{context, register, space, user_op, LANGUAGE_V8, LANGUAGE_V8T};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_v8() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_V8)
    }

    pub fn new_v8t() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_V8T)
    }

    pub fn language(&self) -> &'static Language {
        &__impl::LANGUAGE_V8
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = V8;
    pub const DEFAULT_THUMB: LanguageVariant = V8T;

    pub const V8: LanguageVariant = LanguageVariant::new("v8", &__impl::LANGUAGE_V8);
    pub const V8T: LanguageVariant = LanguageVariant::new("v8T", &__impl::LANGUAGE_V8T);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn variant_tag_matches_factory() {
        assert_eq!(LifterFactory::new_v8().language().variant(), "v8");
        assert_eq!(LifterFactory::new_v8t().language().variant(), "v8T");
    }

    #[test]
    fn variant_language_matches_factory() {
        let v = variants::V8;
        assert!(std::ptr::eq(v.language(), &__impl::LANGUAGE_V8));
        assert_eq!(v.variant(), "v8");
    }
}
