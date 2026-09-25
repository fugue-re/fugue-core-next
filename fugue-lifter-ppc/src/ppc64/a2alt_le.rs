use fugue_lifter_runtime::{Language, Lifter};

mod __impl {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/ppc64_a2alt_le.rs"));
}

pub use __impl::{LANGUAGE_A2ALT, LANGUAGE_A2ALT_32ADDR, context, register, space, user_op};

pub struct LifterFactory;

impl LifterFactory {
    pub fn new_a2alt() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_A2ALT)
    }

    pub fn new_a2alt_32addr() -> Lifter {
        Lifter::new(&__impl::LANGUAGE_A2ALT_32ADDR)
    }
}

pub mod variants {
    use super::*;

    pub const A2ALT: &Language = &__impl::LANGUAGE_A2ALT;
    pub const A2ALT_32ADDR: &Language = &__impl::LANGUAGE_A2ALT_32ADDR;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn variant_tag_matches_factory() {
        assert_eq!(LifterFactory::new_a2alt().language().variant(), "A2ALT");
        assert_eq!(
            LifterFactory::new_a2alt_32addr().language().variant(),
            "A2ALT-32addr"
        );
    }
}
