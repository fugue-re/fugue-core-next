pub(crate) mod recovery;
pub use recovery::{
    FunctionBuilder, FunctionBuilderContext, FunctionDiscoveryContext, FunctionRecovery,
    FunctionRecoveryCommitContext, FunctionRecoveryCommitHook, FunctionRecoveryConfig,
    FunctionRecoveryError, FunctionRecoveryExtension, FunctionRecoveryPatternMatcher,
    FunctionRecoveryPatternMatcherError, FunctionRecoveryState, InsnResolver,
};
