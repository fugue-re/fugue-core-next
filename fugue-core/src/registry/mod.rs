#[doc(hidden)]
pub mod __private {
    pub extern crate inventory;
}

#[doc(hidden)]
#[macro_export]
macro_rules! __fugue_core_registry_collect {
    ($($tokens:tt)*) => {
        $crate::registry::__private::inventory::collect!($($tokens)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __fugue_core_registry_submit {
    ($($tokens:tt)*) => {
        $crate::registry::__private::inventory::submit!($($tokens)*);
    };
}

pub use crate::{__fugue_core_registry_collect as collect, __fugue_core_registry_submit as submit};

mod private {
    pub trait RegistryCollect: Sized + 'static {
        fn iter() -> Box<dyn Iterator<Item = &'static Self>>;
    }

    impl<T> RegistryCollect for T
    where
        T: inventory::Collect,
    {
        fn iter() -> Box<dyn Iterator<Item = &'static Self>> {
            Box::new(inventory::iter::<T>.into_iter())
        }
    }
}

pub trait Collect: private::RegistryCollect {}

impl<T> Collect for T where T: inventory::Collect {}

pub trait Registration: Send + Sync + 'static {
    fn name(&self) -> &'static str;
}

pub fn iter<T>() -> impl Iterator<Item = &'static T>
where
    T: Collect,
{
    <T as private::RegistryCollect>::iter()
}
