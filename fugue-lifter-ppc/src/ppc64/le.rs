use fugue_lifter_runtime::{Language, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/ppc64_le.rs"));
}

pub use __impl::{LANGUAGE_64_32ADDR, LANGUAGE_DEFAULT, context, register, space, user_op};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_default() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_DEFAULT)
    }

    pub fn new_64_32addr() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_64_32ADDR)
    }
}

pub mod variants {
    use super::*;

    pub const DEFAULT: &Language = &__impl::LANGUAGE_DEFAULT;
    pub const V64_32ADDR: &Language = &__impl::LANGUAGE_64_32ADDR;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn variant_tag_matches_factory() {
        assert_eq!(LifterFactory::new_default().language().variant(), "default");
        assert_eq!(
            LifterFactory::new_64_32addr().language().variant(),
            "64-32addr"
        );
    }
}
