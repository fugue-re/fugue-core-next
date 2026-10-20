use std::sync::LazyLock;

use crate::ir::symbol::{SymbolSet, symbol};
use crate::platform::analysis::NonReturningExternalSet;
use crate::platform::{OperatingSystem, Platform};

static WINDOWS_NON_RETURNING: LazyLock<SymbolSet> = LazyLock::new(|| {
    [
        "ExitProcess",
        "ExitThread",
        "FreeLibraryAndExitThread",
        "RaiseFailFastException",
        "RtlExitUserProcess",
        "RtlExitUserThread",
        "KeBugCheck",
        "KeBugCheckEx",
        "abort",
        "exit",
        "_exit",
        "_Exit",
        "quick_exit",
        "_endthread",
        "_endthreadex",
        "_invalid_parameter_noinfo_noreturn",
        "_invoke_watson",
        "_CxxThrowException",
        "?terminate@@YAXXZ",
    ]
    .into_iter()
    .map(symbol)
    .collect()
});

#[fugue_core::extension]
impl NonReturningExternalSet {
    const NAME: &str = "windows";

    fn supports(platform: &Platform) -> bool {
        platform.os() == OperatingSystem::Windows
    }

    fn externals() -> &'static SymbolSet {
        &WINDOWS_NON_RETURNING
    }

    fn symbol_name(name: &str) -> &str {
        name.split_once('!').map_or(name, |(_, name)| name)
    }
}
