use fugue_bv::BitVec;

use crate::analysis::function::recovery::InsnResolver;
use crate::arch::Arch;
use crate::ir::{Address, AddressWithContext, RawAddress, SwitchCase, SwitchEvidence};
use crate::lifter::{ContextSet, LiftingContext};
use crate::storage::SegmentStorage;
use crate::storage::segments::SegmentMappingCache;
use crate::storage::segments::space::AddressSpaceId;

pub(crate) struct SwitchTargetResolver<'a> {
    arch: &'a Arch,
    mapping_cache: SegmentMappingCache<'a>,
    space: AddressSpaceId,
}

impl<'a> SwitchTargetResolver<'a> {
    pub(crate) fn new(arch: &'a Arch, segments: &'a SegmentStorage, space: AddressSpaceId) -> Self {
        Self {
            arch,
            mapping_cache: SegmentMappingCache::new(segments),
            space,
        }
    }

    pub(crate) fn resolve_value(
        &mut self,
        value: &BitVec,
        context: &LiftingContext,
    ) -> Option<AddressWithContext> {
        let (canonical, context) = self
            .arch
            .canonicalise_address_with(RawAddress::from(value.to_u64()?), context)?;
        self.resolve_canonical_address(canonical, context)
    }

    pub(crate) fn resolve_address(
        &mut self,
        value: RawAddress,
        context: &LiftingContext,
    ) -> Option<AddressWithContext> {
        let (canonical, context) = self.arch.canonicalise_address_with(value, context)?;
        self.resolve_canonical_address(canonical, context)
    }

    pub(crate) fn resolve_branch_target(
        &mut self,
        address: Address,
        expected_length: Option<usize>,
        context: &ContextSet,
        resolver: &mut InsnResolver,
    ) -> Option<AddressWithContext> {
        let view = self.mapping_cache.view_containing(address)?;
        let window = view.bytes_from(address)?;
        let bytes = window.as_contiguous()?;
        context.apply(address, resolver.context_mut());
        let instruction = resolver.resolve(address, bytes).ok()?;
        if expected_length.is_some_and(|length| instruction.len() != length)
            || !instruction.is_branch()
            || instruction.is_call()
            || instruction.is_return()
            || instruction.is_indirect()
            || instruction.has_fall()
        {
            return None;
        }
        let mut targets = instruction.iter_targets();
        let (_, _, target) = targets.next()?;
        if targets.next().is_some() {
            return None;
        }
        self.resolve_address(target.raw_address(), resolver.context())
    }

    pub(crate) fn evidence_for_table(
        &mut self,
        table: Address,
        cases: &[SwitchCase],
    ) -> SwitchEvidence {
        let mut evidence = self.evidence_for_targets(cases);
        if self
            .mapping_cache
            .properties_at(table)
            .is_some_and(|properties| properties.is_readable() && !properties.is_writable())
        {
            evidence |= SwitchEvidence::TABLE_IN_READ_ONLY;
        }
        evidence
    }

    pub(crate) fn evidence_for_targets(&self, cases: &[SwitchCase]) -> SwitchEvidence {
        let alignment = self.arch.language().address_alignment() as u64;
        if alignment <= 1
            || cases
                .iter()
                .all(|case| case.target().address().offset() % alignment == 0)
        {
            SwitchEvidence::TARGETS_ALIGNED
        } else {
            SwitchEvidence::empty()
        }
    }

    fn resolve_canonical_address(
        &mut self,
        canonical: RawAddress,
        context: ContextSet,
    ) -> Option<AddressWithContext> {
        let address = Address::new(self.space, canonical);
        let executable = self
            .mapping_cache
            .properties_at(address)
            .is_some_and(|properties| properties.is_executable());
        executable.then(|| AddressWithContext::new(address, context))
    }
}
