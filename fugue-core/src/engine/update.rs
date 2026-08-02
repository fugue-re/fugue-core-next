use std::sync::Arc;

use crate::engine::change::ChangeSet;
use crate::ir::{
    Address, FunctionId, FunctionProperties, IncompleteFunction, ProblemKind, Reference,
    ReferenceOrigin, ReferenceTarget, Switch, SymbolEntry, SymbolIndex,
};
use crate::project::{ProjectError, ProjectTransaction};
use crate::storage::segments::mapping::{
    SegmentMappingFlags, SegmentMappingId, SegmentMappingKind, SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePatch {
    address: Address,
    bytes: Arc<[u8]>,
}

impl BytePatch {
    pub fn new(address: impl Into<Address>, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            address: address.into(),
            bytes: bytes.into(),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPatch {
    function: IncompleteFunction,
}

impl FunctionPatch {
    pub fn new(function: IncompleteFunction) -> Self {
        Self { function }
    }

    pub fn function(&self) -> &IncompleteFunction {
        &self.function
    }

    fn into_function(self) -> IncompleteFunction {
        self.function
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionPropertiesUpdate {
    entry: Address,
    properties: FunctionProperties,
}

impl FunctionPropertiesUpdate {
    pub fn new(entry: impl Into<Address>, properties: FunctionProperties) -> Self {
        Self {
            entry: entry.into(),
            properties,
        }
    }

    pub fn entry(&self) -> Address {
        self.entry
    }

    pub fn properties(&self) -> FunctionProperties {
        self.properties
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolPatch {
    index: SymbolIndex,
    entry: SymbolEntry,
}

impl SymbolPatch {
    pub fn new(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self { index, entry }
    }

    pub fn index(&self) -> SymbolIndex {
        self.index
    }

    pub fn entry(&self) -> &SymbolEntry {
        &self.entry
    }

    fn into_parts(self) -> (SymbolIndex, SymbolEntry) {
        (self.index, self.entry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchPatch {
    asserted: bool,
    switch: Switch,
}

impl SwitchPatch {
    pub fn new(switch: Switch) -> Self {
        Self {
            asserted: true,
            switch,
        }
    }

    fn derived(switch: Switch) -> Self {
        Self {
            asserted: false,
            switch,
        }
    }

    pub fn switch(&self) -> &Switch {
        &self.switch
    }

    fn into_parts(self) -> (Switch, bool) {
        (self.switch, self.asserted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProblemPatch {
    address: Address,
    kind: ProblemKind,
}

impl ProblemPatch {
    pub fn new(address: impl Into<Address>, kind: ProblemKind) -> Self {
        Self {
            address: address.into(),
            kind,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn kind(&self) -> ProblemKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunctionRemovalTarget {
    Address(Address),
    Id(FunctionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionRemoval {
    origin: ReferenceOrigin,
    target: FunctionRemovalTarget,
}

impl FunctionRemoval {
    pub fn new(entry: impl Into<Address>) -> Self {
        Self {
            origin: ReferenceOrigin::Derived,
            target: FunctionRemovalTarget::Address(entry.into()),
        }
    }

    pub fn by_id(id: FunctionId) -> Self {
        Self {
            origin: ReferenceOrigin::Derived,
            target: FunctionRemovalTarget::Id(id),
        }
    }

    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    pub fn set_origin(&mut self, origin: ReferenceOrigin) {
        self.origin = origin;
    }

    pub fn with_origin(mut self, origin: ReferenceOrigin) -> Self {
        self.set_origin(origin);
        self
    }

    pub fn entry(&self) -> Option<Address> {
        match self.target {
            FunctionRemovalTarget::Address(entry) => Some(entry),
            FunctionRemovalTarget::Id(_) => None,
        }
    }

    pub fn id(&self) -> Option<FunctionId> {
        match self.target {
            FunctionRemovalTarget::Address(_) => None,
            FunctionRemovalTarget::Id(id) => Some(id),
        }
    }

    fn apply(self, transaction: &mut ProjectTransaction<'_>) -> Result<(), ProjectError> {
        match self.target {
            FunctionRemovalTarget::Address(entry) => {
                transaction.remove_function(entry, self.origin)?;
            }
            FunctionRemovalTarget::Id(id) => {
                transaction.remove_function_by_id(id, self.origin)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolRemoval {
    index: SymbolIndex,
}

impl SymbolRemoval {
    pub fn new(index: SymbolIndex) -> Self {
        Self { index }
    }

    pub fn index(&self) -> SymbolIndex {
        self.index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceRemoval {
    from: Address,
    target: ReferenceTarget,
}

impl ReferenceRemoval {
    pub fn new(from: Address, target: ReferenceTarget) -> Self {
        Self { from, target }
    }

    pub fn from(&self) -> Address {
        self.from
    }

    pub fn target(&self) -> ReferenceTarget {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingPlacementMode {
    Bottom,
    Default,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingPlacement {
    mapping: SegmentMappingId,
    mode: MappingPlacementMode,
    space: AddressSpaceId,
}

impl MappingPlacement {
    pub fn new(
        space: AddressSpaceId,
        mapping: SegmentMappingId,
        mode: MappingPlacementMode,
    ) -> Self {
        Self {
            mapping,
            mode,
            space,
        }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn mode(&self) -> MappingPlacementMode {
        self.mode
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingPriorityUpdate {
    mapping: SegmentMappingId,
    space: AddressSpaceId,
}

impl MappingPriorityUpdate {
    pub fn new(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self { mapping, space }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingMetadataUpdate {
    flags: SegmentMappingFlags,
    kind: SegmentMappingKind,
    mapping: SegmentMappingId,
    provenance: SegmentMappingProvenance,
}

impl MappingMetadataUpdate {
    pub fn new(mapping: SegmentMappingId) -> Self {
        Self {
            flags: SegmentMappingFlags::default(),
            kind: SegmentMappingKind::default(),
            mapping,
            provenance: SegmentMappingProvenance::default(),
        }
    }

    pub fn flags(&self) -> SegmentMappingFlags {
        self.flags
    }

    pub fn kind(&self) -> SegmentMappingKind {
        self.kind
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn provenance(&self) -> SegmentMappingProvenance {
        self.provenance
    }

    pub fn set_flags(&mut self, flags: SegmentMappingFlags) {
        self.flags = flags;
    }

    pub fn set_kind(&mut self, kind: SegmentMappingKind) {
        self.kind = kind;
    }

    pub fn set_provenance(&mut self, provenance: SegmentMappingProvenance) {
        self.provenance = provenance;
    }

    pub fn with_flags(mut self, flags: SegmentMappingFlags) -> Self {
        self.set_flags(flags);
        self
    }

    pub fn with_kind(mut self, kind: SegmentMappingKind) -> Self {
        self.set_kind(kind);
        self
    }

    pub fn with_provenance(mut self, provenance: SegmentMappingProvenance) -> Self {
        self.set_provenance(provenance);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRemap {
    mapping: SegmentMappingId,
    start: Address,
}

impl MappingRemap {
    pub fn new(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self {
            mapping,
            start: start.into(),
        }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn start(&self) -> Address {
        self.start
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingRemoval {
    mapping: SegmentMappingId,
}

impl MappingRemoval {
    pub fn new(mapping: SegmentMappingId) -> Self {
        Self { mapping }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingResize {
    mapping: SegmentMappingId,
    size: u64,
}

impl MappingResize {
    pub fn new(mapping: SegmentMappingId, size: u64) -> Self {
        Self { mapping, size }
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingCreationResult {
    changes: ChangeSet,
    mapping: SegmentMappingId,
}

impl MappingCreationResult {
    pub fn new(mapping: SegmentMappingId, changes: ChangeSet) -> Self {
        Self { changes, mapping }
    }

    pub fn changes(&self) -> &ChangeSet {
        &self.changes
    }

    pub fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceCreationResult {
    changes: ChangeSet,
    space: AddressSpaceId,
}

impl SpaceCreationResult {
    pub fn new(space: AddressSpaceId, changes: ChangeSet) -> Self {
        Self { changes, space }
    }

    pub fn changes(&self) -> &ChangeSet {
        &self.changes
    }

    pub fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectUpdate {
    AddFunction(FunctionPatch),
    AddMappingToSpace(MappingPlacement),
    AddProblem(ProblemPatch),
    AddReference(Reference),
    AddSwitch(SwitchPatch),
    AddSymbol(SymbolPatch),
    DeprioritiseMapping(MappingPriorityUpdate),
    PrioritiseMapping(MappingPriorityUpdate),
    RemapMapping(MappingRemap),
    RemoveFunction(FunctionRemoval),
    RemoveMapping(MappingRemoval),
    RemoveReference(ReferenceRemoval),
    RemoveSwitch(Address),
    RemoveSymbol(SymbolRemoval),
    ResizeMapping(MappingResize),
    SetFunctionProperties(FunctionPropertiesUpdate),
    UpdateMappingMetadata(MappingMetadataUpdate),
    WriteBytes(BytePatch),
}

impl ProjectUpdate {
    pub fn add_function(function: IncompleteFunction) -> Self {
        Self::AddFunction(FunctionPatch::new(function))
    }

    pub fn add_mapping_to_space(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Default,
        ))
    }

    pub fn add_mapping_to_space_bottom(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Bottom,
        ))
    }

    pub fn add_mapping_to_space_top(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Top,
        ))
    }

    pub fn deprioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::DeprioritiseMapping(MappingPriorityUpdate::new(space, mapping))
    }

    pub fn add_symbol(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self::AddSymbol(SymbolPatch::new(index, entry))
    }

    pub fn prioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::PrioritiseMapping(MappingPriorityUpdate::new(space, mapping))
    }

    pub fn remap_mapping(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self::RemapMapping(MappingRemap::new(mapping, start))
    }

    pub fn remove_function(entry: impl Into<Address>) -> Self {
        Self::RemoveFunction(FunctionRemoval::new(entry))
    }

    pub fn remove_function_by_id(id: FunctionId) -> Self {
        Self::RemoveFunction(FunctionRemoval::by_id(id))
    }

    pub fn remove_mapping(mapping: SegmentMappingId) -> Self {
        Self::RemoveMapping(MappingRemoval::new(mapping))
    }

    pub fn add_reference(reference: Reference) -> Self {
        Self::AddReference(reference)
    }

    pub fn remove_reference(from: Address, target: ReferenceTarget) -> Self {
        Self::RemoveReference(ReferenceRemoval::new(from, target))
    }

    pub fn add_switch(switch: Switch) -> Self {
        Self::AddSwitch(SwitchPatch::new(switch))
    }

    pub(crate) fn add_derived_switch(switch: Switch) -> Self {
        Self::AddSwitch(SwitchPatch::derived(switch))
    }

    pub fn add_problem(address: impl Into<Address>, kind: ProblemKind) -> Self {
        Self::AddProblem(ProblemPatch::new(address, kind))
    }

    pub fn set_function_properties(
        entry: impl Into<Address>,
        properties: FunctionProperties,
    ) -> Self {
        Self::SetFunctionProperties(FunctionPropertiesUpdate::new(entry, properties))
    }

    pub fn remove_switch(branch: impl Into<Address>) -> Self {
        Self::RemoveSwitch(branch.into())
    }

    pub fn remove_symbol(index: SymbolIndex) -> Self {
        Self::RemoveSymbol(SymbolRemoval::new(index))
    }

    pub fn resize_mapping(mapping: SegmentMappingId, size: u64) -> Self {
        Self::ResizeMapping(MappingResize::new(mapping, size))
    }

    pub fn update_mapping_metadata(update: MappingMetadataUpdate) -> Self {
        Self::UpdateMappingMetadata(update)
    }

    pub fn write_bytes(address: impl Into<Address>, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self::WriteBytes(BytePatch::new(address, bytes))
    }

    pub(crate) fn apply(
        self,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
        match self {
            Self::AddFunction(patch) => {
                transaction.add_function(patch.into_function())?;
                Ok(())
            }
            Self::AddMappingToSpace(placement) => match placement.mode() {
                MappingPlacementMode::Bottom => {
                    transaction.add_mapping_to_space_bottom(placement.space(), placement.mapping())
                }
                MappingPlacementMode::Default => {
                    transaction.add_mapping_to_space(placement.space(), placement.mapping())
                }
                MappingPlacementMode::Top => {
                    transaction.add_mapping_to_space_top(placement.space(), placement.mapping())
                }
            },
            Self::DeprioritiseMapping(priority) => {
                transaction.deprioritise_mapping(priority.space(), priority.mapping())
            }
            Self::AddReference(reference) => {
                transaction.add_reference(reference)?;
                Ok(())
            }
            Self::AddSwitch(patch) => {
                let (mut switch, asserted) = patch.into_parts();
                if asserted {
                    switch.mark_override();
                }
                let branch = switch.branch();
                transaction.add_switch(branch, move |id, _| switch.with_id(id))?;
                Ok(())
            }
            Self::AddSymbol(patch) => {
                let (index, entry) = patch.into_parts();
                transaction.add_symbol(index, entry)?;
                Ok(())
            }
            Self::AddProblem(problem) => transaction.add_problem(problem.address(), problem.kind()),
            Self::PrioritiseMapping(priority) => {
                transaction.prioritise_mapping(priority.space(), priority.mapping())
            }
            Self::RemapMapping(remap) => transaction.remap_mapping(remap.mapping(), remap.start()),
            Self::RemoveFunction(removal) => removal.apply(transaction),
            Self::RemoveMapping(removal) => transaction.remove_mapping(removal.mapping()),
            Self::RemoveReference(removal) => {
                transaction.remove_reference(removal.from(), removal.target())?;
                Ok(())
            }
            Self::RemoveSwitch(branch) => {
                transaction.remove_switch(branch)?;
                Ok(())
            }
            Self::RemoveSymbol(removal) => {
                transaction.remove_symbol_by_index(removal.index())?;
                Ok(())
            }
            Self::ResizeMapping(resize) => {
                transaction.resize_mapping(resize.mapping(), resize.size())
            }
            Self::SetFunctionProperties(update) => {
                transaction.set_function_properties(update.entry(), update.properties())?;
                Ok(())
            }
            Self::UpdateMappingMetadata(update) => transaction.update_mapping_metadata(
                update.mapping(),
                update.kind(),
                update.provenance(),
                update.flags(),
            ),
            Self::WriteBytes(patch) => transaction.write_bytes(patch.address(), patch.bytes()),
        }
    }

    pub(crate) fn apply_all(
        updates: impl IntoIterator<Item = Self>,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
        let mut functions = Vec::new();

        for update in updates {
            let update = match update {
                Self::AddFunction(patch) => {
                    functions.push(patch.into_function());
                    continue;
                }
                update => update,
            };

            if !functions.is_empty() {
                transaction.add_functions(functions.drain(..))?;
            }
            update.apply(transaction)?;
        }

        if !functions.is_empty() {
            transaction.add_functions(functions)?;
        }

        Ok(())
    }
}
