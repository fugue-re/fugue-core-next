use std::sync::Arc;

use crate::ir::{
    Address, AddressRangeSet, FunctionId, FunctionProperties, IncompleteFunction, ProblemKind,
    Reference, ReferenceKind, ReferenceOrigin, ReferenceTarget, Switch, SymbolEntry, SymbolIndex,
};
use crate::project::{ChangeSet, ProjectError, ProjectTransaction};
use crate::storage::segments::mapping::{
    SegmentMappingFlags, SegmentMappingId, SegmentMappingKind, SegmentMappingProvenance,
};
use crate::storage::segments::space::AddressSpaceId;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ByteWrite {
    address: Address,
    bytes: Arc<[u8]>,
}

impl ByteWrite {
    fn new(address: impl Into<Address>, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            address: address.into(),
            bytes: bytes.into(),
        }
    }

    fn address(&self) -> Address {
        self.address
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionAddition {
    function: IncompleteFunction,
}

impl FunctionAddition {
    fn new(function: IncompleteFunction) -> Self {
        Self { function }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunctionPropertiesUpdate {
    entry: Address,
    properties: FunctionProperties,
}

impl FunctionPropertiesUpdate {
    fn new(entry: impl Into<Address>, properties: FunctionProperties) -> Self {
        Self {
            entry: entry.into(),
            properties,
        }
    }

    fn entry(&self) -> Address {
        self.entry
    }

    fn properties(&self) -> FunctionProperties {
        self.properties
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SymbolAddition {
    index: SymbolIndex,
    entry: SymbolEntry,
}

impl SymbolAddition {
    fn new(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self { index, entry }
    }

    fn into_parts(self) -> (SymbolIndex, SymbolEntry) {
        (self.index, self.entry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SwitchAddition {
    asserted: bool,
    switch: Switch,
}

impl SwitchAddition {
    fn new(switch: Switch) -> Self {
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

    fn into_parts(self) -> (Switch, bool) {
        (self.switch, self.asserted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProblemAddition {
    address: Address,
    kind: ProblemKind,
}

impl ProblemAddition {
    fn new(address: impl Into<Address>, kind: ProblemKind) -> Self {
        Self {
            address: address.into(),
            kind,
        }
    }

    fn address(&self) -> Address {
        self.address
    }

    fn kind(&self) -> ProblemKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunctionRemovalTarget {
    Address(Address),
    Id(FunctionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunctionRemoval {
    origin: ReferenceOrigin,
    target: FunctionRemovalTarget,
}

impl FunctionRemoval {
    fn new(entry: impl Into<Address>) -> Self {
        Self {
            origin: ReferenceOrigin::Derived,
            target: FunctionRemovalTarget::Address(entry.into()),
        }
    }

    fn by_id(id: FunctionId) -> Self {
        Self {
            origin: ReferenceOrigin::Derived,
            target: FunctionRemovalTarget::Id(id),
        }
    }

    fn asserted(mut self) -> Self {
        self.origin = ReferenceOrigin::Asserted;
        self
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
struct SymbolRemoval {
    index: SymbolIndex,
}

impl SymbolRemoval {
    fn new(index: SymbolIndex) -> Self {
        Self { index }
    }

    fn index(&self) -> SymbolIndex {
        self.index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReferenceRemoval {
    from: Address,
    target: ReferenceTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedReferenceReplacement {
    coverage: AddressRangeSet,
    kind: ReferenceKind,
    references: Vec<Reference>,
}

impl DerivedReferenceReplacement {
    fn new(coverage: AddressRangeSet, kind: ReferenceKind, references: Vec<Reference>) -> Self {
        Self {
            coverage,
            kind,
            references,
        }
    }

    fn apply(self, transaction: &mut ProjectTransaction<'_>) -> Result<(), ProjectError> {
        transaction.replace_derived_references(self.coverage, self.kind, self.references)?;
        Ok(())
    }
}

impl ReferenceRemoval {
    fn new(from: Address, target: ReferenceTarget) -> Self {
        Self { from, target }
    }

    fn from(&self) -> Address {
        self.from
    }

    fn target(&self) -> ReferenceTarget {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappingPlacementMode {
    Bottom,
    Default,
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappingPlacement {
    mapping: SegmentMappingId,
    mode: MappingPlacementMode,
    space: AddressSpaceId,
}

impl MappingPlacement {
    fn new(space: AddressSpaceId, mapping: SegmentMappingId, mode: MappingPlacementMode) -> Self {
        Self {
            mapping,
            mode,
            space,
        }
    }

    fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    fn mode(&self) -> MappingPlacementMode {
        self.mode
    }

    fn space(&self) -> AddressSpaceId {
        self.space
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappingPriorityUpdate {
    mapping: SegmentMappingId,
    space: AddressSpaceId,
}

impl MappingPriorityUpdate {
    fn new(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self { mapping, space }
    }

    fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    fn space(&self) -> AddressSpaceId {
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
struct MappingRemap {
    mapping: SegmentMappingId,
    start: Address,
}

impl MappingRemap {
    fn new(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self {
            mapping,
            start: start.into(),
        }
    }

    fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    fn start(&self) -> Address {
        self.start
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappingRemoval {
    mapping: SegmentMappingId,
}

impl MappingRemoval {
    fn new(mapping: SegmentMappingId) -> Self {
        Self { mapping }
    }

    fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MappingResize {
    mapping: SegmentMappingId,
    size: u64,
}

impl MappingResize {
    fn new(mapping: SegmentMappingId, size: u64) -> Self {
        Self { mapping, size }
    }

    fn mapping(&self) -> SegmentMappingId {
        self.mapping
    }

    fn size(&self) -> u64 {
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
pub struct ProjectUpdate {
    operation: ProjectOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectOperation {
    AddFunction(FunctionAddition),
    AddMappingToSpace(MappingPlacement),
    AddProblem(ProblemAddition),
    AddReference(Reference),
    AddSwitch(SwitchAddition),
    AddSymbol(SymbolAddition),
    DeprioritiseMapping(MappingPriorityUpdate),
    PrioritiseMapping(MappingPriorityUpdate),
    RemapMapping(MappingRemap),
    RemoveFunction(FunctionRemoval),
    RemoveMapping(MappingRemoval),
    RemoveReference(ReferenceRemoval),
    RemoveSwitch(Address),
    RemoveSymbol(SymbolRemoval),
    ReplaceDerivedReferences(DerivedReferenceReplacement),
    ResizeMapping(MappingResize),
    UpdateFunctionProperties(FunctionPropertiesUpdate),
    UpdateMappingMetadata(MappingMetadataUpdate),
    WriteBytes(ByteWrite),
}

impl ProjectUpdate {
    pub fn add_function(function: IncompleteFunction) -> Self {
        Self::new(ProjectOperation::AddFunction(FunctionAddition::new(
            function,
        )))
    }

    pub fn add_mapping_to_space(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::new(ProjectOperation::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Default,
        )))
    }

    pub fn add_mapping_to_space_bottom(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::new(ProjectOperation::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Bottom,
        )))
    }

    pub fn add_mapping_to_space_top(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::new(ProjectOperation::AddMappingToSpace(MappingPlacement::new(
            space,
            mapping,
            MappingPlacementMode::Top,
        )))
    }

    pub fn deprioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::new(ProjectOperation::DeprioritiseMapping(
            MappingPriorityUpdate::new(space, mapping),
        ))
    }

    pub fn add_symbol(index: SymbolIndex, entry: SymbolEntry) -> Self {
        Self::new(ProjectOperation::AddSymbol(SymbolAddition::new(
            index, entry,
        )))
    }

    pub fn prioritise_mapping(space: AddressSpaceId, mapping: SegmentMappingId) -> Self {
        Self::new(ProjectOperation::PrioritiseMapping(
            MappingPriorityUpdate::new(space, mapping),
        ))
    }

    pub fn remap_mapping(mapping: SegmentMappingId, start: impl Into<Address>) -> Self {
        Self::new(ProjectOperation::RemapMapping(MappingRemap::new(
            mapping, start,
        )))
    }

    pub fn remove_function(entry: impl Into<Address>) -> Self {
        Self::new(ProjectOperation::RemoveFunction(FunctionRemoval::new(
            entry,
        )))
    }

    pub fn remove_function_by_id(id: FunctionId) -> Self {
        Self::new(ProjectOperation::RemoveFunction(FunctionRemoval::by_id(id)))
    }

    pub(crate) fn remove_asserted_function(entry: impl Into<Address>) -> Self {
        Self::new(ProjectOperation::RemoveFunction(
            FunctionRemoval::new(entry).asserted(),
        ))
    }

    pub(crate) fn remove_asserted_function_by_id(id: FunctionId) -> Self {
        Self::new(ProjectOperation::RemoveFunction(
            FunctionRemoval::by_id(id).asserted(),
        ))
    }

    pub fn remove_mapping(mapping: SegmentMappingId) -> Self {
        Self::new(ProjectOperation::RemoveMapping(MappingRemoval::new(
            mapping,
        )))
    }

    pub fn add_reference(reference: Reference) -> Self {
        Self::new(ProjectOperation::AddReference(reference))
    }

    pub fn remove_reference(from: Address, target: ReferenceTarget) -> Self {
        Self::new(ProjectOperation::RemoveReference(ReferenceRemoval::new(
            from, target,
        )))
    }

    pub fn replace_derived_references(
        coverage: AddressRangeSet,
        kind: ReferenceKind,
        references: Vec<Reference>,
    ) -> Self {
        Self::new(ProjectOperation::ReplaceDerivedReferences(
            DerivedReferenceReplacement::new(coverage, kind, references),
        ))
    }

    pub fn add_switch(switch: Switch) -> Self {
        Self::new(ProjectOperation::AddSwitch(SwitchAddition::new(switch)))
    }

    pub(crate) fn add_derived_switch(switch: Switch) -> Self {
        Self::new(ProjectOperation::AddSwitch(SwitchAddition::derived(switch)))
    }

    pub fn add_problem(address: impl Into<Address>, kind: ProblemKind) -> Self {
        Self::new(ProjectOperation::AddProblem(ProblemAddition::new(
            address, kind,
        )))
    }

    pub fn update_function_properties(
        entry: impl Into<Address>,
        properties: FunctionProperties,
    ) -> Self {
        Self::new(ProjectOperation::UpdateFunctionProperties(
            FunctionPropertiesUpdate::new(entry, properties),
        ))
    }

    pub fn remove_switch(branch: impl Into<Address>) -> Self {
        Self::new(ProjectOperation::RemoveSwitch(branch.into()))
    }

    pub fn remove_symbol(index: SymbolIndex) -> Self {
        Self::new(ProjectOperation::RemoveSymbol(SymbolRemoval::new(index)))
    }

    pub fn resize_mapping(mapping: SegmentMappingId, size: u64) -> Self {
        Self::new(ProjectOperation::ResizeMapping(MappingResize::new(
            mapping, size,
        )))
    }

    pub fn update_mapping_metadata(update: MappingMetadataUpdate) -> Self {
        Self::new(ProjectOperation::UpdateMappingMetadata(update))
    }

    pub fn write_bytes(address: impl Into<Address>, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self::new(ProjectOperation::WriteBytes(ByteWrite::new(address, bytes)))
    }

    fn new(operation: ProjectOperation) -> Self {
        Self { operation }
    }

    pub(crate) fn apply_all(
        updates: impl IntoIterator<Item = Self>,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
        let mut functions = Vec::new();

        for update in updates {
            let update = match update.operation {
                ProjectOperation::AddFunction(addition) => {
                    functions.push(addition.function);
                    continue;
                }
                operation => Self::new(operation),
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

    pub(crate) fn apply(
        self,
        transaction: &mut ProjectTransaction<'_>,
    ) -> Result<(), ProjectError> {
        match self.operation {
            ProjectOperation::AddFunction(addition) => {
                transaction.add_function(addition.function)?;
                Ok(())
            }
            ProjectOperation::AddMappingToSpace(placement) => match placement.mode() {
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
            ProjectOperation::DeprioritiseMapping(priority) => {
                transaction.deprioritise_mapping(priority.space(), priority.mapping())
            }
            ProjectOperation::AddReference(reference) => {
                transaction.add_reference(reference)?;
                Ok(())
            }
            ProjectOperation::AddSwitch(addition) => {
                let (mut switch, asserted) = addition.into_parts();
                if asserted {
                    switch.mark_override();
                }
                let branch = switch.branch();
                transaction.add_switch(branch, move |id, _| switch.with_id(id))?;
                Ok(())
            }
            ProjectOperation::AddSymbol(addition) => {
                let (index, entry) = addition.into_parts();
                transaction.add_symbol(index, entry)?;
                Ok(())
            }
            ProjectOperation::AddProblem(problem) => {
                transaction.add_problem(problem.address(), problem.kind())
            }
            ProjectOperation::PrioritiseMapping(priority) => {
                transaction.prioritise_mapping(priority.space(), priority.mapping())
            }
            ProjectOperation::RemapMapping(remap) => {
                transaction.remap_mapping(remap.mapping(), remap.start())
            }
            ProjectOperation::RemoveFunction(removal) => removal.apply(transaction),
            ProjectOperation::RemoveMapping(removal) => {
                transaction.remove_mapping(removal.mapping())
            }
            ProjectOperation::RemoveReference(removal) => {
                transaction.remove_reference(removal.from(), removal.target())?;
                Ok(())
            }
            ProjectOperation::RemoveSwitch(branch) => {
                transaction.remove_switch(branch)?;
                Ok(())
            }
            ProjectOperation::RemoveSymbol(removal) => {
                transaction.remove_symbol_by_index(removal.index())?;
                Ok(())
            }
            ProjectOperation::ReplaceDerivedReferences(replacement) => {
                replacement.apply(transaction)
            }
            ProjectOperation::ResizeMapping(resize) => {
                transaction.resize_mapping(resize.mapping(), resize.size())
            }
            ProjectOperation::UpdateFunctionProperties(update) => {
                transaction.update_function_properties(update.entry(), update.properties())?;
                Ok(())
            }
            ProjectOperation::UpdateMappingMetadata(update) => transaction.update_mapping_metadata(
                update.mapping(),
                update.kind(),
                update.provenance(),
                update.flags(),
            ),
            ProjectOperation::WriteBytes(write) => {
                transaction.write_bytes(write.address(), write.bytes())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ir::{
        ReferenceProperties, SwitchId, SwitchModel, SymbolProperties, SymbolTableSelector, symbol,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TransactionVerb {
        AddFunction,
        AddMappingToSpace,
        AddMappingToSpaceBottom,
        AddMappingToSpaceTop,
        AddProblem,
        AddReference,
        AddSwitch,
        AddSymbol,
        DeprioritiseMapping,
        PrioritiseMapping,
        RemapMapping,
        RemoveAssertedFunction,
        RemoveAssertedFunctionById,
        RemoveDerivedFunction,
        RemoveDerivedFunctionById,
        RemoveMapping,
        RemoveReference,
        RemoveSwitch,
        RemoveSymbol,
        ReplaceDerivedReferences,
        ResizeMapping,
        UpdateFunctionProperties,
        UpdateMappingMetadata,
        WriteBytes,
    }

    fn transaction_verb(update: ProjectUpdate) -> TransactionVerb {
        match update.operation {
            ProjectOperation::AddFunction(_) => TransactionVerb::AddFunction,
            ProjectOperation::AddMappingToSpace(placement) => match placement.mode {
                MappingPlacementMode::Bottom => TransactionVerb::AddMappingToSpaceBottom,
                MappingPlacementMode::Default => TransactionVerb::AddMappingToSpace,
                MappingPlacementMode::Top => TransactionVerb::AddMappingToSpaceTop,
            },
            ProjectOperation::AddProblem(_) => TransactionVerb::AddProblem,
            ProjectOperation::AddReference(_) => TransactionVerb::AddReference,
            ProjectOperation::AddSwitch(_) => TransactionVerb::AddSwitch,
            ProjectOperation::AddSymbol(_) => TransactionVerb::AddSymbol,
            ProjectOperation::DeprioritiseMapping(_) => TransactionVerb::DeprioritiseMapping,
            ProjectOperation::PrioritiseMapping(_) => TransactionVerb::PrioritiseMapping,
            ProjectOperation::RemapMapping(_) => TransactionVerb::RemapMapping,
            ProjectOperation::RemoveFunction(removal) => match (removal.origin, removal.target) {
                (ReferenceOrigin::Asserted, FunctionRemovalTarget::Address(_)) => {
                    TransactionVerb::RemoveAssertedFunction
                }
                (ReferenceOrigin::Asserted, FunctionRemovalTarget::Id(_)) => {
                    TransactionVerb::RemoveAssertedFunctionById
                }
                (ReferenceOrigin::Derived, FunctionRemovalTarget::Address(_)) => {
                    TransactionVerb::RemoveDerivedFunction
                }
                (ReferenceOrigin::Derived, FunctionRemovalTarget::Id(_)) => {
                    TransactionVerb::RemoveDerivedFunctionById
                }
            },
            ProjectOperation::RemoveMapping(_) => TransactionVerb::RemoveMapping,
            ProjectOperation::RemoveReference(_) => TransactionVerb::RemoveReference,
            ProjectOperation::RemoveSwitch(_) => TransactionVerb::RemoveSwitch,
            ProjectOperation::RemoveSymbol(_) => TransactionVerb::RemoveSymbol,
            ProjectOperation::ReplaceDerivedReferences(_) => {
                TransactionVerb::ReplaceDerivedReferences
            }
            ProjectOperation::ResizeMapping(_) => TransactionVerb::ResizeMapping,
            ProjectOperation::UpdateFunctionProperties(_) => {
                TransactionVerb::UpdateFunctionProperties
            }
            ProjectOperation::UpdateMappingMetadata(_) => TransactionVerb::UpdateMappingMetadata,
            ProjectOperation::WriteBytes(_) => TransactionVerb::WriteBytes,
        }
    }

    #[test]
    fn every_update_constructor_selects_one_transaction_verb() {
        let address = Address::from(0x1000u64);
        let function = FunctionId::INVALID;
        let mapping = SegmentMappingId::new(1);
        let space = AddressSpaceId::new(1);
        let symbol_index = SymbolIndex::new(SymbolTableSelector::new(0), 0);
        let symbol_entry = SymbolEntry::new(address, symbol("entry"), SymbolProperties::default());
        let reference = Reference::data(address, address, ReferenceProperties::default());
        let switch = Switch::new(SwitchId::INVALID, address, SwitchModel::Explicit);

        let cases = [
            (
                "add_function",
                ProjectUpdate::add_function(IncompleteFunction::new(address)),
                TransactionVerb::AddFunction,
            ),
            (
                "add_mapping_to_space",
                ProjectUpdate::add_mapping_to_space(space, mapping),
                TransactionVerb::AddMappingToSpace,
            ),
            (
                "add_mapping_to_space_bottom",
                ProjectUpdate::add_mapping_to_space_bottom(space, mapping),
                TransactionVerb::AddMappingToSpaceBottom,
            ),
            (
                "add_mapping_to_space_top",
                ProjectUpdate::add_mapping_to_space_top(space, mapping),
                TransactionVerb::AddMappingToSpaceTop,
            ),
            (
                "add_problem",
                ProjectUpdate::add_problem(address, ProblemKind::Unknown),
                TransactionVerb::AddProblem,
            ),
            (
                "add_reference",
                ProjectUpdate::add_reference(reference),
                TransactionVerb::AddReference,
            ),
            (
                "add_switch",
                ProjectUpdate::add_switch(switch.clone()),
                TransactionVerb::AddSwitch,
            ),
            (
                "add_derived_switch",
                ProjectUpdate::add_derived_switch(switch),
                TransactionVerb::AddSwitch,
            ),
            (
                "add_symbol",
                ProjectUpdate::add_symbol(symbol_index, symbol_entry),
                TransactionVerb::AddSymbol,
            ),
            (
                "deprioritise_mapping",
                ProjectUpdate::deprioritise_mapping(space, mapping),
                TransactionVerb::DeprioritiseMapping,
            ),
            (
                "prioritise_mapping",
                ProjectUpdate::prioritise_mapping(space, mapping),
                TransactionVerb::PrioritiseMapping,
            ),
            (
                "remap_mapping",
                ProjectUpdate::remap_mapping(mapping, address),
                TransactionVerb::RemapMapping,
            ),
            (
                "remove_function",
                ProjectUpdate::remove_function(address),
                TransactionVerb::RemoveDerivedFunction,
            ),
            (
                "remove_function_by_id",
                ProjectUpdate::remove_function_by_id(function),
                TransactionVerb::RemoveDerivedFunctionById,
            ),
            (
                "remove_asserted_function",
                ProjectUpdate::remove_asserted_function(address),
                TransactionVerb::RemoveAssertedFunction,
            ),
            (
                "remove_asserted_function_by_id",
                ProjectUpdate::remove_asserted_function_by_id(function),
                TransactionVerb::RemoveAssertedFunctionById,
            ),
            (
                "remove_mapping",
                ProjectUpdate::remove_mapping(mapping),
                TransactionVerb::RemoveMapping,
            ),
            (
                "remove_reference",
                ProjectUpdate::remove_reference(address, address.into()),
                TransactionVerb::RemoveReference,
            ),
            (
                "remove_switch",
                ProjectUpdate::remove_switch(address),
                TransactionVerb::RemoveSwitch,
            ),
            (
                "remove_symbol",
                ProjectUpdate::remove_symbol(symbol_index),
                TransactionVerb::RemoveSymbol,
            ),
            (
                "replace_derived_references",
                ProjectUpdate::replace_derived_references(
                    AddressRangeSet::new(),
                    ReferenceKind::Data,
                    Vec::new(),
                ),
                TransactionVerb::ReplaceDerivedReferences,
            ),
            (
                "resize_mapping",
                ProjectUpdate::resize_mapping(mapping, 1),
                TransactionVerb::ResizeMapping,
            ),
            (
                "update_function_properties",
                ProjectUpdate::update_function_properties(address, FunctionProperties::NONE),
                TransactionVerb::UpdateFunctionProperties,
            ),
            (
                "update_mapping_metadata",
                ProjectUpdate::update_mapping_metadata(MappingMetadataUpdate::new(mapping)),
                TransactionVerb::UpdateMappingMetadata,
            ),
            (
                "write_bytes",
                ProjectUpdate::write_bytes(address, Arc::<[u8]>::from([0u8])),
                TransactionVerb::WriteBytes,
            ),
        ];

        for (constructor, update, expected) in cases {
            assert_eq!(transaction_verb(update), expected, "{constructor}");
        }
    }
}
