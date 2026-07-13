use crate::analysis::AnalysisError;
use crate::analysis::function::recovery::FunctionRecoveryPatternMatcher;
use crate::arch::Arch;
use crate::platform::CallingConvention;

pub const X86_GCC: &str = include_str!("./x86-gcc.yml");
pub const X86_64_GCC: &str = include_str!("./x86-64-gcc.yml");

pub(crate) struct FunctionRecoveryPatterns;

impl FunctionRecoveryPatterns {
    pub(crate) fn apply(
        arch: &Arch,
        convention: CallingConvention,
        analyser: &mut FunctionRecoveryPatternMatcher,
    ) -> Result<(), AnalysisError> {
        let language = arch.language();
        let processor = language.processor();
        let is_be = language.is_big_endian();
        let bits = language.address_bits();

        match (processor, is_be, bits) {
            ("x86", false, 32) => Self::apply_x86(convention, analyser),
            ("x86", false, 64) => Self::apply_x86_64(convention, analyser),
            _ => Ok(()),
        }
    }

    fn apply_x86(
        convention: CallingConvention,
        analyser: &mut FunctionRecoveryPatternMatcher,
    ) -> Result<(), AnalysisError> {
        match convention {
            CallingConvention::Gcc => {
                analyser.add_patterns_from_str(X86_GCC).map_err(|e| {
                    AnalysisError::pass_configuration_failed("function-recovery", e)
                })?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn apply_x86_64(
        convention: CallingConvention,
        analyser: &mut FunctionRecoveryPatternMatcher,
    ) -> Result<(), AnalysisError> {
        match convention {
            CallingConvention::Gcc => {
                analyser.add_patterns_from_str(X86_64_GCC).map_err(|e| {
                    AnalysisError::pass_configuration_failed("function-recovery", e)
                })?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
