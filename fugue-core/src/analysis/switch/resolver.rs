use fugue_bv::BitVec;
use fugue_bytes::Endian;

use crate::analysis::function::recovery::InsnResolver;
use crate::arch::Arch;
use crate::ir::{Address, AddressWithContext, RawAddress, SwitchCase, SwitchProperties};
use crate::lifter::{ContextSet, LiftingContext};
use crate::storage::{AddressSpaceId, SegmentMappingCache, SegmentStorage};

pub(crate) struct SwitchTargetResolver<'a> {
    arch: &'a Arch,
    mapping_cache: SegmentMappingCache,
    read_buffer: Vec<u8>,
    segments: &'a SegmentStorage,
    space: AddressSpaceId,
}

impl<'a> SwitchTargetResolver<'a> {
    pub(crate) fn new(arch: &'a Arch, segments: &'a SegmentStorage, space: AddressSpaceId) -> Self {
        Self {
            arch,
            mapping_cache: SegmentMappingCache::new(),
            read_buffer: Vec::new(),
            segments,
            space,
        }
    }

    pub(crate) fn resolve_value(
        &mut self,
        value: &BitVec,
        context: &LiftingContext,
    ) -> Option<AddressWithContext> {
        self.resolve_address(RawAddress::from(value.to_u64()?), context)
    }

    pub(crate) fn set_space(&mut self, space: AddressSpaceId) {
        self.space = space;
    }

    pub(crate) fn mapping_cache_mut(&mut self) -> &mut SegmentMappingCache {
        &mut self.mapping_cache
    }

    pub(crate) fn segments(&self) -> &'a SegmentStorage {
        self.segments
    }

    pub(crate) fn read_bitvec(&mut self, address: Address, size: usize) -> Option<BitVec> {
        self.read_buffer.resize(size, 0);
        if self
            .mapping_cache
            .read_bytes_exact(self.segments, address, &mut self.read_buffer)
            .is_err()
        {
            return None;
        }
        let value = match self.arch.endian() {
            Endian::Big => BitVec::from_be_bytes(&self.read_buffer),
            Endian::Little => BitVec::from_le_bytes(&self.read_buffer),
        };
        Some(value)
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
        let view = self
            .mapping_cache
            .contiguous_bytes_from(self.segments, address)
            .ok()?;
        let bytes = view.as_contiguous()?;
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

    pub(crate) fn properties_for_table(
        &mut self,
        table: Address,
        cases: &[SwitchCase],
    ) -> SwitchProperties {
        let mut properties = self.properties_for_targets(cases);
        if self
            .mapping_cache
            .segment_properties(self.segments, table)
            .is_some_and(|properties| properties.is_readable() && !properties.is_writable())
        {
            properties |= SwitchProperties::TABLE_IN_READ_ONLY;
        }
        properties
    }

    pub(crate) fn properties_for_targets(&self, cases: &[SwitchCase]) -> SwitchProperties {
        let alignment = self.arch.language().address_alignment() as u64;
        if alignment <= 1
            || cases
                .iter()
                .all(|case| case.target().address().offset() % alignment == 0)
        {
            SwitchProperties::TARGETS_ALIGNED
        } else {
            SwitchProperties::empty()
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
            .segment_properties(self.segments, address)
            .is_some_and(|properties| properties.is_executable());
        executable.then(|| AddressWithContext::new(address, context))
    }
}
