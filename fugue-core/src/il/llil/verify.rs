use crate::il::common::{IlError, Verify};
use crate::il::llil::LlilBody;

#[derive(Debug, Copy, Clone, Default)]
pub struct LlilVerifier;

impl LlilVerifier {
    pub fn verify_body(body: &LlilBody) -> Result<(), IlError> {
        body.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{ArtefactHeader, BuildStatus, CommonBody, Finish, IrLevel};
    use crate::il::llil::{LLIL_SCHEMA_VERSION, LlilBuilder};
    use crate::ir::FunctionId;

    #[test]
    fn llil_verifier_accepts_verified_body() {
        let header =
            ArtefactHeader::new(FunctionId::default(), IrLevel::Llil, LLIL_SCHEMA_VERSION, 0);
        let body = LlilBuilder::new(header, CommonBody::default())
            .finish(&BuildStatus::new())
            .unwrap();

        assert_eq!(LlilVerifier::verify_body(&body), Ok(()));
    }
}
