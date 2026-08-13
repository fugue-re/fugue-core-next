use super::ProjectTransaction;
use crate::il::common::IlArtefact;
use crate::il::pcode::PCodeIr;
use crate::ir::{Address, AddressRange, ProblemKind, RawAddress};
use crate::project::{ChangeRecord, ProjectError};
use crate::storage::SegmentStorageError;
use crate::storage::segments::mapping::{
    SegmentMappingBuilder, SegmentMappingFlags, SegmentMappingId, SegmentMappingKind,
    SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;

impl ProjectTransaction<'_> {
    pub fn create_mapping(
        &mut self,
        builder: SegmentMappingBuilder,
    ) -> Result<SegmentMappingId, ProjectError> {
        let mapping = self
            .segment_staging
            .create_mapping(self.project.storage.segments(), builder)?;
        self.changes
            .push(ChangeRecord::SegmentMappingCreated { mapping });
        Ok(mapping)
    }

    pub fn create_space(&mut self) -> Result<AddressSpaceId, ProjectError> {
        let space = self
            .segment_staging
            .create_space(self.project.storage.segments())?;
        self.changes.push(ChangeRecord::SpaceCreated { space });
        Ok(space)
    }

    pub fn add_mapping_to_space(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_staging
            .add_mapping(self.project.storage.segments(), space, mapping)?;
        self.record_mapping_added(space, mapping)?;
        self.invalidate_functions_for_mapping(space, mapping)?;

        Ok(())
    }

    pub fn add_mapping_to_space_top(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_staging
            .add_mapping_top(self.project.storage.segments(), space, mapping)?;
        self.record_mapping_added(space, mapping)?;
        self.invalidate_functions_for_mapping(space, mapping)?;

        Ok(())
    }

    pub fn add_mapping_to_space_bottom(
        &mut self,
        space: AddressSpaceId,
        mapping: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_staging
            .add_mapping_bottom(self.project.storage.segments(), space, mapping)?;
        self.record_mapping_added(space, mapping)?;
        self.invalidate_functions_for_mapping(space, mapping)?;

        Ok(())
    }

    pub fn remove_mapping(&mut self, id: SegmentMappingId) -> Result<(), ProjectError> {
        let removed = self
            .segment_staging
            .remove_mapping(self.project.storage.segments(), id)?;
        self.record_mapping_removed(id, removed.iter().copied());
        self.invalidate_functions_for_placements(removed)?;

        Ok(())
    }

    pub fn remap_mapping(
        &mut self,
        id: SegmentMappingId,
        new_start: impl Into<Address>,
    ) -> Result<(), ProjectError> {
        let new_start = new_start.into();
        let removed = self
            .segment_staging
            .mapping_placements(self.project.storage.segments(), id)?;
        self.segment_staging
            .remap_mapping(self.project.storage.segments(), id, new_start)?;
        self.record_mapping_removed(id, removed.iter().copied());
        self.invalidate_functions_for_placements(removed)?;
        self.record_mapping_added_to_placements(id)?;
        self.invalidate_functions_for_mapping_placements(id)?;

        Ok(())
    }

    pub fn resize_mapping(
        &mut self,
        id: SegmentMappingId,
        new_size: u64,
    ) -> Result<(), ProjectError> {
        let removed = self
            .segment_staging
            .mapping_placements(self.project.storage.segments(), id)?;
        self.segment_staging
            .resize_mapping(self.project.storage.segments(), id, new_size)?;
        self.record_mapping_removed(id, removed.iter().copied());
        self.invalidate_functions_for_placements(removed)?;
        self.record_mapping_added_to_placements(id)?;
        self.invalidate_functions_for_mapping_placements(id)?;

        Ok(())
    }

    pub fn update_mapping_metadata(
        &mut self,
        id: SegmentMappingId,
        kind: SegmentMappingKind,
        provenance: SegmentMappingProvenance,
        flags: SegmentMappingFlags,
    ) -> Result<(), ProjectError> {
        self.segment_staging.update_mapping_metadata(
            self.project.storage.segments(),
            id,
            kind,
            provenance,
            flags,
        )?;
        self.changes
            .push(ChangeRecord::SegmentMappingChanged { mapping: id });

        Ok(())
    }

    pub fn prioritise_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_staging
            .prioritise_mapping(self.project.storage.segments(), space, id)?;
        self.record_mapping_added(space, id)?;
        self.invalidate_functions_for_mapping(space, id)?;

        Ok(())
    }

    pub fn deprioritise_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        self.segment_staging
            .deprioritise_mapping(self.project.storage.segments(), space, id)?;
        self.record_mapping_added(space, id)?;
        self.invalidate_functions_for_mapping(space, id)?;

        Ok(())
    }

    pub fn write_bytes(&mut self, addr: Address, bytes: &[u8]) -> Result<(), ProjectError> {
        let (written, revert) = self
            .project
            .storage
            .segments_mut()
            .write_bytes_to_space_tracked(addr.space(), addr, bytes)?;

        if written == bytes.len() {
            self.segment_write_reverts.push(revert);
            if let Some(range) = AddressRange::from_size(addr, written as u64) {
                self.changes.push(ChangeRecord::BytesWritten { range });
                self.invalidate_functions_in_range(&range)?;
            }
            Ok(())
        } else {
            revert.restore(self.project.storage.segments_mut())?;
            Err(SegmentStorageError::InvalidAddressRange.into())
        }
    }

    pub fn write_bytes_in_space(
        &mut self,
        space: AddressSpaceId,
        addr: impl Into<RawAddress>,
        bytes: &[u8],
    ) -> Result<(), ProjectError> {
        let addr = Address::new(space, addr.into());
        self.write_bytes(addr, bytes)
    }

    fn invalidate_functions_for_mapping(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let Some(range) =
            self.segment_staging
                .mapping_range(self.project.storage.segments(), space, id)?
        else {
            return Ok(0);
        };
        self.invalidate_functions_in_range(&range)
    }

    fn invalidate_functions_for_mapping_placements(
        &mut self,
        id: SegmentMappingId,
    ) -> Result<usize, ProjectError> {
        let placements = self
            .segment_staging
            .mapping_placements(self.project.storage.segments(), id)?;

        self.invalidate_functions_for_placements(placements)
    }

    fn invalidate_functions_for_placements(
        &mut self,
        placements: impl IntoIterator<Item = AddressRange>,
    ) -> Result<usize, ProjectError> {
        let mut invalidated = 0usize;

        for range in placements {
            invalidated += self.invalidate_functions_in_range(&range)?;
        }

        Ok(invalidated)
    }

    fn invalidate_functions_in_range(
        &mut self,
        range: &AddressRange,
    ) -> Result<usize, ProjectError> {
        let functions = self.project.functions.staged_overlaps(
            &self.project.blocks,
            &self.function_staging,
            range,
        )?;
        let mut invalidated = 0usize;

        for id in functions {
            let Some(origin) = self
                .project
                .functions
                .staged_origin(&self.function_staging, id)?
            else {
                continue;
            };

            if origin.is_asserted() {
                let function = self
                    .project
                    .functions
                    .staged_by_id(&self.function_staging, id)?
                    .expect("staged function origin requires a function");
                self.remove_lifted_descendants(id, &PCodeIr::FORM)?;
                self.add_problem(function.entry(), ProblemKind::HinderedByAssertedFact)?;
            } else if self.stage_function_removal(id)?.is_some() {
                invalidated += 1;
            }
        }

        Ok(invalidated)
    }

    fn record_mapping_added(
        &mut self,
        space: AddressSpaceId,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        if let Some(range) =
            self.segment_staging
                .mapping_range(self.project.storage.segments(), space, id)?
        {
            self.changes
                .push(ChangeRecord::SegmentMapped { mapping: id, range });
        }
        Ok(())
    }

    fn record_mapping_added_to_placements(
        &mut self,
        id: SegmentMappingId,
    ) -> Result<(), ProjectError> {
        let added = self
            .segment_staging
            .mapping_placements(self.project.storage.segments(), id)?;

        for range in added {
            self.changes
                .push(ChangeRecord::SegmentMapped { mapping: id, range });
        }
        Ok(())
    }

    fn record_mapping_removed(
        &mut self,
        id: SegmentMappingId,
        removed: impl IntoIterator<Item = AddressRange>,
    ) {
        for range in removed {
            self.changes
                .push(ChangeRecord::SegmentUnmapped { mapping: id, range });
        }
    }
}
