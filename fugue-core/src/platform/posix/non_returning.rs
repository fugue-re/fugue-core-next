use std::sync::LazyLock;

use crate::ir::symbol::{SymbolSet, symbol};
use crate::platform::analysis::NonReturningExternalSet;
use crate::platform::{OperatingSystem, Platform};

static POSIX_NON_RETURNING: LazyLock<SymbolSet> = LazyLock::new(|| {
    [
        "abort",
        "exit",
        "_exit",
        "_Exit",
        "quick_exit",
        "longjmp",
        "_longjmp",
        "siglongjmp",
        "__longjmp_chk",
        "__stack_chk_fail",
        "__fortify_fail",
        "__chk_fail",
        "__assert_fail",
        "__assert_perror_fail",
        "__assert_rtn",
        "err",
        "errx",
        "verr",
        "verrx",
        "pthread_exit",
        "__libc_fatal",
        "__cxa_throw",
        "__cxa_rethrow",
        "__cxa_bad_cast",
        "__cxa_bad_typeid",
        "__cxa_call_unexpected",
        "__cxa_pure_virtual",
        "__cxa_deleted_virtual",
        "_Unwind_Resume",
        "_ZSt9terminatev",
        "_ZSt10unexpectedv",
        "_ZN10__cxxabiv111__terminateEPFvvE",
        "_ZN10__cxxabiv112__unexpectedEPFvvE",
    ]
    .into_iter()
    .map(symbol)
    .collect()
});

#[fugue_core::extension]
impl NonReturningExternalSet {
    const NAME: &str = "posix";

    fn supports(platform: &Platform) -> bool {
        matches!(
            platform.os(),
            OperatingSystem::FreeBsd | OperatingSystem::Linux | OperatingSystem::Macos
        )
    }

    fn externals() -> &'static SymbolSet {
        &POSIX_NON_RETURNING
    }

    fn symbol_name(name: &str) -> &str {
        name
    }
}
