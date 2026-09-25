#[doc(hidden)]
pub mod __private {
    pub extern crate inventory;
}

#[doc(hidden)]
#[macro_export]
macro_rules! __fugue_core_extension_collect {
    ($($tokens:tt)*) => {
        $crate::extension::__private::inventory::collect!($($tokens)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __fugue_core_extension_submit {
    ($($tokens:tt)*) => {
        $crate::extension::__private::inventory::submit!($($tokens)*);
    };
}

pub use crate::{
    __fugue_core_extension_collect as collect, __fugue_core_extension_submit as submit,
};

mod private {
    pub trait ExtensionCollect: Sized + 'static {
        fn iter() -> Box<dyn Iterator<Item = &'static Self>>;
    }

    impl<T> ExtensionCollect for T
    where
        T: inventory::Collect,
    {
        fn iter() -> Box<dyn Iterator<Item = &'static Self>> {
            Box::new(inventory::iter::<T>.into_iter())
        }
    }
}

pub trait Collect: private::ExtensionCollect {}

impl<T> Collect for T where T: inventory::Collect {}

pub trait Registration: Send + Sync + 'static {
    fn name(&self) -> &'static str;
}

pub fn iter<T>() -> impl Iterator<Item = &'static T>
where
    T: Collect,
{
    <T as private::ExtensionCollect>::iter()
}
