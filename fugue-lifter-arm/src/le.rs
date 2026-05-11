use fugue_lifter_runtime::{Language, LanguageVariant, Lifter, LiftingContext};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/arm_le.rs"));
}
pub use __impl::{context, register, space, user_op, LANGUAGE_V8, LANGUAGE_V8T};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_v8() -> Lifter {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 0);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        Lifter::new(
            &__impl::LANGUAGE_V8,
            __impl::lifter_with(&__impl::LANGUAGE_V8, 2, base),
        )
    }

    pub fn new_v8t() -> Lifter {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 1);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        Lifter::new(
            &__impl::LANGUAGE_V8T,
            __impl::lifter_with(&__impl::LANGUAGE_V8T, 2, base),
        )
    }

    pub fn language(&self) -> &'static Language {
        &__impl::LANGUAGE_V8
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

        __impl::lifter_with(&__impl::LANGUAGE_V8, 2, base)
    }

    pub fn new_v8t() -> LiftingContext {
        let mut base = __impl::default_context();

        base.set_variable_default_by_bits(context::T_MODE, 1);
        base.set_variable_default_by_bits(context::L_RSET, 0);

        __impl::lifter_with(&__impl::LANGUAGE_V8T, 2, base)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: LanguageVariant = V8;
    pub const DEFAULT_THUMB: LanguageVariant = V8T;

    pub const V8: LanguageVariant =
        LanguageVariant::new("v8", &__impl::LANGUAGE_V8, LiftingContextFactory::new_v8);
    pub const V8T: LanguageVariant =
        LanguageVariant::new("v8T", &__impl::LANGUAGE_V8T, LiftingContextFactory::new_v8t);
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
    fn variant_language_matches_factory_context() {
        let v = variants::V8;
        let v_ctx = (v.context())();
        assert!(std::ptr::eq(v.language(), v_ctx.language()));
        assert!(std::ptr::eq(v.language(), &__impl::LANGUAGE_V8));
    }
}
