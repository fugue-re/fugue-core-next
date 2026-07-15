use crate::il::common::{IlError, Verify};
use crate::il::pcode::PCodeBody;

#[derive(Debug, Copy, Clone, Default)]
pub struct PCodeVerifier;

impl PCodeVerifier {
    pub fn verify_body(body: &PCodeBody) -> Result<(), IlError> {
        body.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel};
    use crate::il::pcode::{PCODE_SCHEMA_VERSION, PCodeBuilder};
    use crate::ir::FunctionId;

    #[test]
    fn pcode_verifier_accepts_verified_body() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            0,
        );
        let body = PCodeBuilder::new(header, CommonBody::default())
            .finish(&BuildStatus::new())
            .unwrap();

        assert_eq!(PCodeVerifier::verify_body(&body), Ok(()));
    }
}
