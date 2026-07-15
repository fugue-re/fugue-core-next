use fugue_lifter::runtime::language::Language;
use fugue_lifter::{Op, PCodeOp};
use smallvec::SmallVec;

use crate::il::common::{
    ArtefactHeader, BuildCancellation, CommonBody, Finish, IlError, OperationId,
};
use crate::il::pcode::{
    AddressAnnotation, AddressAnnotationPayload, PCodeAddressContext, PCodeBody, PCodeBuilder,
    PCodeError,
};
use crate::ir::{Address, Insn, InsnTarget};

#[derive(Debug, Default)]
pub struct PCodeCanonicaliser;

impl PCodeCanonicaliser {
    pub fn canonicalise_stream(
        &mut self,
        header: ArtefactHeader,
        common: CommonBody,
        operations: &[PCodeOp],
        language: &'static Language,
        context: &mut PCodeAddressContext<'_>,
        cancellation: &(impl BuildCancellation + ?Sized),
    ) -> Result<PCodeBody, PCodeError> {
        let mut builder = PCodeBuilder::new(header, common);

        builder.push_lifter_stream(operations, language, context)?;

        Ok(builder.finish(cancellation)?)
    }

    pub fn push_direct_target_annotations(
        language: &'static Language,
        address: Address,
        length: usize,
        operations: &[PCodeOp],
        starting_ordinal: usize,
        annotations: &mut Vec<AddressAnnotation<'static>>,
    ) -> Result<usize, PCodeError> {
        let mut targets = SmallVec::<[(u16, InsnTarget); 2]>::new();
        Insn::push_targets_for_operations(language, address, length, operations, &mut targets);
        let mut semantic_count = 0usize;
        let mut index = 0usize;

        while let Some(operation) = operations.get(index) {
            let ordinal_index = starting_ordinal
                .checked_add(semantic_count)
                .ok_or(IlError::integer_overflow("PCode operation index"))?;
            let ordinal = OperationId::try_from_index(ordinal_index)?;

            if operation.is_arg() {
                return Err(PCodeError::misplaced_arg(ordinal.value()));
            }

            if matches!(operation.op(), Op::Branch | Op::CBranch | Op::Call)
                && let Some(target) = targets
                    .iter()
                    .find(|(target_index, _)| usize::from(*target_index) == index)
                    .and_then(|(_, target)| target.address())
            {
                annotations.push(AddressAnnotation::new(
                    ordinal,
                    AddressAnnotationPayload::DirectTarget(target),
                ));
            }

            semantic_count += 1;
            index += operation.spill() + 1;
        }

        Ok(semantic_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{BuildStatus, IrLevel};
    use crate::il::pcode::PCODE_SCHEMA_VERSION;
    use crate::ir::{Address, FunctionId};
    use crate::lifter::resolve_language;
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn canonicaliser_builds_empty_stream() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            PCODE_SCHEMA_VERSION,
            3,
        );
        let source = Address::new(AddressSpaceId::new(1), 0x1000u64);
        let mut context = PCodeAddressContext::new(source, &[]);
        let mut canonicaliser = PCodeCanonicaliser;
        let language = resolve_language("x86:LE:64").expect("test language should resolve");

        let body = canonicaliser
            .canonicalise_stream(
                header,
                CommonBody::default(),
                &[],
                language,
                &mut context,
                &BuildStatus::new(),
            )
            .unwrap();

        assert!(body.operations().is_empty());
        assert_eq!(body.header().input_revision(), 3);
    }
}
