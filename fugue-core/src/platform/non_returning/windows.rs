use super::NonReturningExterns;
use crate::registry;

static WINDOWS_NON_RETURNING: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "ExitProcess",
    "ExitThread",
    "TerminateProcess",
    "TerminateThread",
    "FreeLibraryAndExitThread",
    "crtExitProcess",
    "__crtExitProcess",
    "RaiseException",
    "RtlRaiseException",
    "RaiseFailFastException",
    "RpcRaiseException",
    "__fastfail",
    "invalid_parameter_noinfo_noreturn",
    "_invalid_parameter_noinfo_noreturn",
    "invoke_watson",
    "_invoke_watson",
    "__report_gsfailure",
    "CxxThrowException",
    "_CxxThrowException",
    "CxxThrowException@8",
    "_CxxThrowException@8",
    "CxxFrameHandler3",
    "__CxxFrameHandler3",
    "terminate",
    "longjmp",
    "_longjmp",
    "__longjmp",
    "KeBugCheck",
    "KeBugCheckEx",
    "ExRaiseStatus",
    "ExRaiseAccessViolation",
    "ExRaiseDatatypeMisalignment",
];

registry::submit! {
    NonReturningExterns::new("windows-non-returning", WINDOWS_NON_RETURNING)
}
