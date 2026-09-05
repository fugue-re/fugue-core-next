use fugue_bv::BitVec;
use fugue_bytes::Endian;

use crate::arch::Arch;
use crate::ir::{
    Address, AddressWithContext, IncompleteCodeBlockId, IncompleteFunction, RawAddress, SwitchCase,
    SwitchProperties,
};
use crate::lifter::{ContextSet, InsnResolver, RawPCodeOp};
use crate::storage::{SegmentMappingCache, SegmentStorage};

pub(crate) struct SwitchResolver<'project, 'resolver> {
    arch: &'project Arch,
    resolver: &'resolver mut InsnResolver,
    mapping_cache: SegmentMappingCache,
    read_buffer: Vec<u8>,
    segments: &'project SegmentStorage,
}

impl<'project, 'resolver> SwitchResolver<'project, 'resolver> {
    pub(crate) fn new(
        arch: &'project Arch,
        segments: &'project SegmentStorage,
        resolver: &'resolver mut InsnResolver,
    ) -> Self {
        Self {
            arch,
            resolver,
            mapping_cache: SegmentMappingCache::new(),
            read_buffer: Vec::new(),
            segments,
        }
    }

    pub(crate) fn apply_context(&mut self, address: Address, context: &ContextSet) {
        context.apply(address, self.resolver.context_mut());
    }

    pub(crate) fn lift_block(
        &mut self,
        function: &IncompleteFunction,
        block: IncompleteCodeBlockId,
        output: &mut Vec<RawPCodeOp>,
    ) -> Option<()> {
        let block = function.block(block)?;
        block
            .context()
            .apply(block.address(), self.resolver.context_mut());
        let view = self
            .mapping_cache
            .contiguous_view_from(self.segments, block.address())
            .ok()?;
        let bytes = view.as_contiguous()?.get(..block.size())?;
        let output_start = output.len();

        for &insn_id in block.insn_ids() {
            let insn = function.insn(insn_id)?;
            let offset = usize::from(insn.address() - block.address());
            if self
                .resolver
                .lift_into(insn.address(), bytes.get(offset..)?, output)
                .is_err()
            {
                output.truncate(output_start);
                return None;
            }
        }
        Some(())
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

    pub(crate) fn resolve_value(
        &mut self,
        source: Address,
        value: &BitVec,
    ) -> Option<AddressWithContext> {
        self.resolve_address(source, RawAddress::from(value.to_u64()?))
    }

    pub(crate) fn resolve_address(
        &mut self,
        source: Address,
        value: RawAddress,
    ) -> Option<AddressWithContext> {
        let (canonical, context) = self
            .arch
            .canonicalise_address_with(value, self.resolver.context())?;
        let address = Address::new(source.space(), canonical);
        let executable = self
            .mapping_cache
            .mapping_properties(self.segments, address)
            .is_some_and(|properties| properties.is_executable());
        executable.then(|| AddressWithContext::new(address, context))
    }

    pub(crate) fn resolve_branch_target(
        &mut self,
        address: Address,
        expected_size: Option<usize>,
        context: &ContextSet,
    ) -> Option<AddressWithContext> {
        let view = self
            .mapping_cache
            .contiguous_view_from(self.segments, address)
            .ok()?;
        let bytes = view.as_contiguous()?;
        context.apply(address, self.resolver.context_mut());
        let instruction = self.resolver.resolve(address, bytes).ok()?;
        let instruction = instruction.as_ref();
        if expected_size.is_some_and(|size| instruction.size() != size)
            || !instruction.is_branch()
            || instruction.is_call()
            || instruction.is_return()
            || instruction.is_indirect()
            || instruction.has_fall_through()
        {
            return None;
        }
        let mut targets = instruction.iter_targets();
        let (_, _, target) = targets.next()?;
        if targets.next().is_some() {
            return None;
        }
        self.resolve_address(address, target.raw_address())
    }

    pub(crate) fn properties_for_table(
        &mut self,
        table: Address,
        cases: &[SwitchCase],
    ) -> SwitchProperties {
        let mut properties = self.properties_for_targets(cases);
        if self
            .mapping_cache
            .mapping_properties(self.segments, table)
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
}
