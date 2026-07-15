use std::cmp::Ordering;

use digest::Digest as _;
use rkyv::Archived;
use sha2::Sha256;

use crate::il::common::{
    Block, BlockId, DialectId, IlError, IrArtefactKey, IrLevel, MappingRun, PredecessorIndex,
    SchemaVersion, SourceRun, StructuralVerifier, Verify,
};
use crate::ir::{Address, AddressRangeSet, FunctionId, Reference};
use crate::storage::entities::schema::ENTITY_IR_ARTEFACT_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
#[repr(transparent)]
pub struct ArtefactDigest([u8; 32]);

impl ArtefactDigest {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ArtefactHeader {
    function: FunctionId,
    level: IrLevel,
    dialect: DialectId,
    schema: SchemaVersion,
    input_revision: u64,
    parent_digest: ArtefactDigest,
    address_topology_digest: ArtefactDigest,
    transform_digest: ArtefactDigest,
    content_digest: ArtefactDigest,
}

impl ArtefactHeader {
    pub const fn new(
        function: FunctionId,
        level: IrLevel,
        schema: SchemaVersion,
        input_revision: u64,
    ) -> Self {
        Self {
            function,
            level,
            dialect: level.dialect_id(),
            schema,
            input_revision,
            parent_digest: ArtefactDigest::ZERO,
            address_topology_digest: ArtefactDigest::ZERO,
            transform_digest: ArtefactDigest::ZERO,
            content_digest: ArtefactDigest::ZERO,
        }
    }

    pub const fn function(&self) -> FunctionId {
        self.function
    }

    pub const fn level(&self) -> IrLevel {
        self.level
    }

    pub const fn dialect(&self) -> DialectId {
        self.dialect
    }

    pub const fn schema(&self) -> SchemaVersion {
        self.schema
    }

    pub const fn input_revision(&self) -> u64 {
        self.input_revision
    }

    pub fn set_input_revision(&mut self, revision: u64) {
        self.input_revision = revision;
    }

    pub const fn parent_digest(&self) -> ArtefactDigest {
        self.parent_digest
    }

    pub fn set_parent_digest(&mut self, digest: ArtefactDigest) {
        self.parent_digest = digest;
    }

    pub const fn address_topology_digest(&self) -> ArtefactDigest {
        self.address_topology_digest
    }

    pub fn set_address_topology_digest(&mut self, digest: ArtefactDigest) {
        self.address_topology_digest = digest;
    }

    pub const fn transform_digest(&self) -> ArtefactDigest {
        self.transform_digest
    }

    pub fn set_transform_digest(&mut self, digest: ArtefactDigest) {
        self.transform_digest = digest;
    }

    pub const fn content_digest(&self) -> ArtefactDigest {
        self.content_digest
    }

    pub fn set_content_digest(&mut self, digest: ArtefactDigest) {
        self.content_digest = digest;
    }

    pub fn verify_schema(&self, level: IrLevel, schema: SchemaVersion) -> Result<(), IlError> {
        self.verify_level(level)?;

        if self.schema != schema {
            return Err(IlError::schema_mismatch(
                level,
                schema.value(),
                self.schema.value(),
            ));
        }

        Ok(())
    }

    pub fn verify_level(&self, level: IrLevel) -> Result<(), IlError> {
        if self.level != level {
            return Err(IlError::unexpected_level(level, self.level));
        }

        if self.dialect != level.dialect_id() {
            return Err(IlError::dialect_mismatch(level.dialect_id(), self.dialect));
        }

        Ok(())
    }

    pub fn verify_identity(&self, function: FunctionId, level: IrLevel) -> Result<(), IlError> {
        if self.function != function {
            return Err(IlError::unexpected_function(function, self.function));
        }

        self.verify_level(level)
    }

    pub fn verify_input_revision(&self, revision: u64) -> Result<(), IlError> {
        if self.input_revision != revision {
            return Err(IlError::stale_artefact(
                self.level,
                revision,
                self.input_revision,
            ));
        }

        Ok(())
    }
}

pub trait IrArtefact: Verify {
    const LEVEL: IrLevel;
    const SCHEMA: SchemaVersion;

    fn header(&self) -> &ArtefactHeader;
    fn header_mut(&mut self) -> &mut ArtefactHeader;
    fn common(&self) -> &CommonBody;
    fn to_raw_artefact(&self) -> Result<RawIrArtefact, IlError>;
    fn from_raw_artefact(artefact: RawIrArtefact) -> Result<Self, IlError>
    where
        Self: Sized;

    fn verify_raw_artefact(artefact: &RawIrArtefact) -> Result<(), IlError>
    where
        Self: Sized,
    {
        Self::from_raw_artefact(artefact.clone()).map(drop)
    }

    fn verify_header(&self) -> Result<(), IlError> {
        self.header().verify_schema(Self::LEVEL, Self::SCHEMA)
    }

    fn collect_reference_coverage(&self, _coverage: &mut AddressRangeSet) {}

    fn collect_derived_references(&self, _references: &mut Vec<Reference>) {}
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct CommonBody {
    blocks: Vec<Block>,
    successors: Vec<BlockId>,
    source_runs: Vec<SourceRun>,
    mapping_runs: Vec<MappingRun>,
}

impl CommonBody {
    pub fn new(
        blocks: Vec<Block>,
        successors: Vec<BlockId>,
        source_runs: Vec<SourceRun>,
        mapping_runs: Vec<MappingRun>,
    ) -> Self {
        Self {
            blocks,
            successors,
            source_runs,
            mapping_runs,
        }
    }

    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn successors(&self) -> &[BlockId] {
        &self.successors
    }

    pub fn source_runs(&self) -> &[SourceRun] {
        &self.source_runs
    }

    pub fn mapping_runs(&self) -> &[MappingRun] {
        &self.mapping_runs
    }

    pub fn entry_block(&self) -> Result<BlockId, IlError> {
        for (index, block) in self.blocks.iter().enumerate() {
            if block.is_entry() {
                return BlockId::try_from_index(index);
            }
        }

        BlockId::try_from_index(0)
    }

    pub fn predecessors(&self) -> Result<PredecessorIndex, IlError> {
        PredecessorIndex::build(&self.blocks, &self.successors)
    }

    pub fn source_for_destination(&self, node: u32) -> Option<SourceRun> {
        self.source_runs
            .binary_search_by(|run| {
                if run.contains_destination(node) {
                    Ordering::Equal
                } else if node < run.destination().start() as u32 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()
            .map(|index| self.source_runs[index])
    }

    pub fn destinations_for_source(
        &self,
        machine_address: Address,
        pcode_index: u32,
    ) -> impl Iterator<Item = SourceRun> + '_ {
        self.source_runs
            .iter()
            .copied()
            .filter(move |run| run.contains_source(machine_address, pcode_index))
    }

    pub fn mapping_for_destination(&self, node: u32) -> Option<MappingRun> {
        self.mapping_runs
            .binary_search_by(|run| {
                if run.contains_destination(node) {
                    Ordering::Equal
                } else if node < run.destination().start() as u32 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()
            .map(|index| self.mapping_runs[index])
    }

    pub fn mappings_for_source(&self, node: u32) -> impl Iterator<Item = MappingRun> + '_ {
        self.mapping_runs
            .iter()
            .copied()
            .filter(move |run| run.contains_source(node))
    }

    pub fn shrink_to_fit(&mut self) {
        self.blocks.shrink_to_fit();
        self.successors.shrink_to_fit();
        self.source_runs.shrink_to_fit();
        self.mapping_runs.shrink_to_fit();
    }

    fn update_digest(&self, digest: &mut Sha256) {
        digest.update((self.blocks.len() as u64).to_be_bytes());

        for block in &self.blocks {
            block.operations().update_digest(digest);
            block.successors().update_digest(digest);
            digest.update(block.flags().to_be_bytes());
        }

        digest.update((self.successors.len() as u64).to_be_bytes());

        for successor in &self.successors {
            digest.update(successor.value().to_be_bytes());
        }

        digest.update((self.source_runs.len() as u64).to_be_bytes());

        for run in &self.source_runs {
            run.update_digest(digest);
        }

        digest.update((self.mapping_runs.len() as u64).to_be_bytes());

        for run in &self.mapping_runs {
            run.update_digest(digest);
        }
    }
}

impl Verify for CommonBody {
    fn verify(&self) -> Result<(), IlError> {
        StructuralVerifier::verify_blocks(&self.blocks, &self.successors)?;
        StructuralVerifier::verify_source_runs(&self.source_runs)?;
        StructuralVerifier::verify_mapping_runs(&self.mapping_runs)?;

        Ok(())
    }
}

impl CommonBody {
    pub fn verify_node_bounds(&self, node_count: usize) -> Result<(), IlError> {
        StructuralVerifier::verify_block_operation_bounds(&self.blocks, node_count)?;
        StructuralVerifier::verify_source_run_bounds(&self.source_runs, node_count)?;
        StructuralVerifier::verify_mapping_destination_bounds(&self.mapping_runs, node_count)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct RawIrArtefact {
    header: ArtefactHeader,
    body: CommonBody,
    payload: Vec<u8>,
}

impl RawIrArtefact {
    pub fn new(mut header: ArtefactHeader, body: CommonBody, payload: Vec<u8>) -> Self {
        header.set_content_digest(Self::content_digest_for(&body, &payload));

        Self {
            header,
            body,
            payload,
        }
    }

    pub const fn header(&self) -> &ArtefactHeader {
        &self.header
    }

    pub const fn body(&self) -> &CommonBody {
        &self.body
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn set_input_revision(&mut self, revision: u64) {
        self.header.set_input_revision(revision);
    }

    pub fn set_parent_digest(&mut self, digest: ArtefactDigest) {
        self.header.set_parent_digest(digest);
    }

    pub fn shrink_to_fit(&mut self) {
        self.body.shrink_to_fit();
        self.payload.shrink_to_fit();
        self.header.set_content_digest(self.content_digest());
    }

    pub fn content_digest(&self) -> ArtefactDigest {
        Self::content_digest_for(&self.body, &self.payload)
    }

    pub fn verify_identity(&self, function: FunctionId, level: IrLevel) -> Result<(), IlError> {
        self.header.verify_identity(function, level)
    }

    pub fn verify_as<T>(&self) -> Result<(), IlError>
    where
        T: IrArtefact,
    {
        T::verify_raw_artefact(self)
    }

    pub fn verify_archived(bytes: &[u8]) -> Result<(), IlError> {
        rkyv::access::<Archived<Self>, rkyv::rancor::Error>(bytes)
            .map(drop)
            .map_err(|_| IlError::artefact_envelope_decode())
    }

    fn content_digest_for(body: &CommonBody, payload: &[u8]) -> ArtefactDigest {
        let mut digest = Sha256::new();

        body.update_digest(&mut digest);
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload);

        let digest = digest.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);

        ArtefactDigest::new(bytes)
    }
}

impl Entity for RawIrArtefact {
    const ID: EntityId = ENTITY_IR_ARTEFACT_ID;
}

impl MutableEntity for RawIrArtefact {
    type Key = IrArtefactKey;

    fn entity_key(&self) -> IrArtefactKey {
        IrArtefactKey::new(self.header.function(), self.header.level())
    }
}

impl Verify for RawIrArtefact {
    fn verify(&self) -> Result<(), IlError> {
        self.header
            .verify_schema(self.header.level(), self.header.schema())?;
        self.body.verify()?;

        if self.content_digest() != self.header.content_digest() {
            return Err(IlError::digest_mismatch());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il::common::{PackedRange, SourceRun};
    use crate::ir::{Address, RawAddress};
    use crate::storage::segments::space::AddressSpaceId;

    #[test]
    fn common_body_rejects_overlapping_source_runs() {
        let address = Address::new(AddressSpaceId::new(1), RawAddress::from(0x1000u64));
        let body = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![
                SourceRun::new(PackedRange::new(0, 2).unwrap(), address, 0, 1),
                SourceRun::new(PackedRange::new(1, 3).unwrap(), address, 1, 1),
            ],
            Vec::new(),
        );

        assert!(matches!(
            body.verify(),
            Err(IlError::OverlappingSourceRun { .. })
        ));
    }

    #[test]
    fn common_body_queries_source_runs_without_map_materialisation() {
        let base = Address::new(AddressSpaceId::new(1), RawAddress::from(0x1000u64));
        let overlay = Address::new(AddressSpaceId::new(2), RawAddress::from(0x1000u64));
        let body = CommonBody::new(
            Vec::new(),
            Vec::new(),
            vec![
                SourceRun::new(PackedRange::new(0, 2).unwrap(), base, 0, 2),
                SourceRun::new(PackedRange::new(2, 4).unwrap(), overlay, 0, 2),
            ],
            Vec::new(),
        );

        assert_eq!(
            body.source_for_destination(1).unwrap().machine_address(),
            base
        );
        assert_eq!(
            body.source_for_destination(3).unwrap().machine_address(),
            overlay
        );
        assert_eq!(body.destinations_for_source(base, 1).count(), 1);
        assert_eq!(body.destinations_for_source(overlay, 1).count(), 1);
    }

    #[test]
    fn common_body_queries_mapping_runs_without_map_materialisation() {
        let body = CommonBody::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                MappingRun::new(
                    PackedRange::new(0, 2).unwrap(),
                    PackedRange::new(4, 6).unwrap(),
                ),
                MappingRun::new(
                    PackedRange::new(2, 4).unwrap(),
                    PackedRange::new(8, 10).unwrap(),
                ),
            ],
        );

        assert_eq!(
            body.mapping_for_destination(3).unwrap().source(),
            PackedRange::new(8, 10).unwrap()
        );
        assert_eq!(body.mappings_for_source(5).count(), 1);
        assert_eq!(body.mappings_for_source(7).count(), 0);
    }

    #[test]
    fn common_body_shrinks_spare_capacity() {
        let mut blocks = Vec::with_capacity(4);
        blocks.push(Block::new(
            PackedRange::EMPTY,
            PackedRange::EMPTY,
            Block::ENTRY,
        ));
        let mut source_runs = Vec::with_capacity(4);
        source_runs.push(SourceRun::new(
            PackedRange::new(0, 1).unwrap(),
            Address::new(AddressSpaceId::new(1), RawAddress::from(0x1000u64)),
            0,
            1,
        ));
        let mut body = CommonBody::new(blocks, Vec::new(), source_runs, Vec::new());

        body.shrink_to_fit();

        assert_eq!(body.blocks.len(), body.blocks.capacity());
        assert_eq!(body.source_runs.len(), body.source_runs.capacity());
    }

    #[test]
    fn raw_artefact_shrink_updates_content_digest() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            SchemaVersion::new(1),
            7,
        );
        let mut payload = Vec::with_capacity(16);
        payload.extend([1, 2, 3]);
        let mut artefact = RawIrArtefact::new(header, CommonBody::default(), payload);

        artefact.shrink_to_fit();

        assert_eq!(
            artefact.content_digest(),
            artefact.header().content_digest()
        );
        assert!(artefact.verify().is_ok());
    }

    #[test]
    fn raw_artefact_reports_entity_key() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            SchemaVersion::new(1),
            7,
        );
        let artefact = RawIrArtefact::new(header, CommonBody::default(), Vec::new());

        assert_eq!(
            artefact.entity_key(),
            IrArtefactKey::new(FunctionId::default(), IrLevel::PCode)
        );
    }

    #[test]
    fn raw_artefact_verifies_archived_envelope() -> Result<(), Box<dyn std::error::Error>> {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            SchemaVersion::new(1),
            7,
        );
        let artefact = RawIrArtefact::new(header, CommonBody::default(), vec![1, 2, 3]);
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&artefact)?;
        let mut truncated = bytes.to_vec();
        truncated.truncate(truncated.len() / 2);

        assert!(RawIrArtefact::verify_archived(&bytes).is_ok());
        assert!(matches!(
            RawIrArtefact::verify_archived(&truncated),
            Err(IlError::ArtefactEnvelopeDecode)
        ));

        Ok(())
    }

    #[test]
    fn raw_artefact_verifies_content_digest() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            SchemaVersion::new(1),
            7,
        );
        let artefact = RawIrArtefact::new(header, CommonBody::default(), vec![1, 2, 3]);

        assert_eq!(
            artefact.content_digest(),
            artefact.header().content_digest()
        );
        assert!(artefact.verify().is_ok());
    }

    #[test]
    fn raw_artefact_rejects_content_digest_mismatch() {
        let header = ArtefactHeader::new(
            FunctionId::default(),
            IrLevel::PCode,
            SchemaVersion::new(1),
            7,
        );
        let artefact = RawIrArtefact {
            header,
            body: CommonBody::default(),
            payload: vec![1, 2, 3],
        };

        assert!(matches!(artefact.verify(), Err(IlError::DigestMismatch)));
    }
}
