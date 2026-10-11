use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::{
    FUNCTION_RECOVERY_ANALYSER, FunctionRecoveryPatternMatcher,
};
use crate::arch::Arch;
use crate::platform::CallingConvention;

pub const X86_GCC: &str = include_str!("./x86-gcc.yml");
pub const X86_64_GCC: &str = include_str!("./x86-64-gcc.yml");

pub(crate) fn apply(
    arch: &Arch,
    convention: CallingConvention,
    analyser: &mut FunctionRecoveryPatternMatcher,
) -> Result<(), AnalysisError> {
    let language = arch.language();
    let processor = language.processor();
    let is_be = language.is_big_endian();
    let bits = language.address_bits();

    let patterns = match (processor, is_be, bits, convention) {
        ("x86", false, 32, CallingConvention::Gcc) => X86_GCC,
        ("x86", false, 64, CallingConvention::Gcc) => X86_64_GCC,
        _ => return Ok(()),
    };
    analyser.add_patterns_from_str(patterns).map_err(|error| {
        AnalysisError::pass_configuration_failed(FUNCTION_RECOVERY_ANALYSER, error)
    })?;
    Ok(())
}
