use crate::il::common::{IlError, Verify};
use crate::il::llil::ssa::SsaBody;

#[derive(Debug, Copy, Clone, Default)]
pub struct SsaVerifier;

impl SsaVerifier {
    pub fn verify_body(body: &SsaBody) -> Result<(), IlError> {
        body.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel};
    use crate::il::llil::ssa::{LLIL_SSA_SCHEMA_VERSION, SsaBuilder};
    use crate::ir::FunctionId;

    #[test]
    fn ssa_verifier_accepts_verified_body() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::LlilSsa,
            LLIL_SSA_SCHEMA_VERSION,
            0,
        );
        let body = SsaBuilder::new(header, CommonBody::default())
            .finish(&BuildStatus::new())
            .unwrap();

        assert_eq!(SsaVerifier::verify_body(&body), Ok(()));
    }
}
