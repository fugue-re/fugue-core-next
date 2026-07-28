use std::sync::LazyLock;

use crate::ir::symbol::{SymbolSet, symbol};
use crate::platform::OperatingSystem;
use crate::platform::non_returning::NonReturningExterns;

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
impl NonReturningExterns {
    const NAME: &str = "windows";
    const OPERATING_SYSTEMS: &[OperatingSystem] = &[OperatingSystem::Windows];

    fn externs() -> &'static SymbolSet {
        &WINDOWS_NON_RETURNING
    }
}
