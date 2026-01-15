use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::core::patterns::FunctionRecoveryPatternMatcher;
use crate::arch::Arch;

pub const X86_GCC: &'static str = include_str!("./x86-gcc.yml");
pub const X86_64_GCC: &'static str = include_str!("./x86-64-gcc.yml");

pub(crate) fn configure_x86_64_analyser(
    _arch: &Arch,
    convention: &str,
    analyser: &mut FunctionRecoveryPatternMatcher,
) -> Result<(), AnalysisError> {
    match convention {
        "gcc" => {
            analyser
                .add_patterns_from_str(X86_64_GCC)
                .map_err(|e| AnalysisError::pass_configuration_failed("function-recovery", e))?;
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn configure_x86_analyser(
    _arch: &Arch,
    convention: &str,
    analyser: &mut FunctionRecoveryPatternMatcher,
) -> Result<(), AnalysisError> {
    match convention {
        "gcc" => {
            analyser
                .add_patterns_from_str(X86_GCC)
                .map_err(|e| AnalysisError::pass_configuration_failed("function-recovery", e))?;
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn configure_analyser(
    arch: &Arch,
    convention: &str,
    analyser: &mut FunctionRecoveryPatternMatcher,
) -> Result<(), AnalysisError> {
    let language = arch.language();
    let processor = language.processor();
    let is_be = language.is_big_endian();
    let bits = language.address_bits();

    match (processor, is_be, bits) {
        ("x86", false, 32) => configure_x86_analyser(arch, convention, analyser),
        ("x86", false, 64) => configure_x86_64_analyser(arch, convention, analyser),
        _ => Ok(()),
    }
}
