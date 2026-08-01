use smallvec::SmallVec;

use crate::ir::{
    Address, AddressTable, AddressWithContext, FunctionId, Id, RawAddress, Reference,
    ReferenceOrigin, ReferenceProperties,
};
use crate::storage::entities::schema::ENTITY_SWITCH_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::types::Confidence;
use crate::types::common::archived_bitflags;

mod table;
pub use table::{SwitchRef, SwitchTable, SwitchTableError};

pub type SwitchId = Id<Switch>;

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Switch {
    id: SwitchId,
    function: FunctionId,
    branch: Address,
    model: SwitchModel,
    cases: Vec<SwitchCase>,
    default: Option<SwitchCase>,
    properties: SwitchProperties,
}

impl AsRef<Switch> for Switch {
    fn as_ref(&self) -> &Switch {
        self
    }
}

impl AsMut<Switch> for Switch {
    fn as_mut(&mut self) -> &mut Switch {
        self
    }
}

impl Entity for Switch {
    const ID: EntityId = ENTITY_SWITCH_ID;
}

impl MutableEntity for Switch {
    type Key = SwitchId;

    fn entity_key(&self) -> SwitchId {
        self.id
    }
}

impl Switch {
    pub fn new(id: SwitchId, branch: Address, model: SwitchModel) -> Self {
        Self {
            id,
            function: FunctionId::INVALID,
            branch,
            model,
            cases: Vec::new(),
            default: None,
            properties: SwitchProperties::empty(),
        }
    }

    pub fn with_id(mut self, id: SwitchId) -> Self {
        self.id = id;
        self
    }

    pub fn with_function(mut self, function: FunctionId) -> Self {
        self.set_function(function);
        self
    }

    pub fn id(&self) -> SwitchId {
        self.id
    }

    pub fn function(&self) -> FunctionId {
        self.function
    }

    pub fn set_function(&mut self, function: FunctionId) {
        self.function = function;
    }

    pub fn branch(&self) -> Address {
        self.branch
    }

    pub fn model(&self) -> &SwitchModel {
        &self.model
    }

    pub fn cases(&self) -> &[SwitchCase] {
        &self.cases
    }

    pub fn case_count(&self) -> usize {
        self.cases.len()
    }

    pub fn add_case(&mut self, case: SwitchCase) {
        self.cases.push(case);
    }

    pub fn set_cases(&mut self, cases: Vec<SwitchCase>) {
        self.cases = cases;
    }

    pub fn with_cases(mut self, cases: Vec<SwitchCase>) -> Self {
        self.set_cases(cases);
        self
    }

    pub fn default_case(&self) -> Option<&SwitchCase> {
        self.default.as_ref()
    }

    pub fn set_default_case(&mut self, case: SwitchCase) {
        self.default = Some(case);
    }

    pub fn confidence(&self) -> Confidence {
        self.properties.confidence()
    }

    pub fn properties(&self) -> SwitchProperties {
        self.properties
    }

    pub fn set_properties(&mut self, properties: SwitchProperties) {
        self.properties = properties;
    }

    pub fn with_properties(mut self, properties: SwitchProperties) -> Self {
        self.set_properties(properties);
        self
    }

    pub fn mark_truncated(&mut self) {
        self.properties.insert(SwitchProperties::TRUNCATED);
    }

    pub fn mark_override(&mut self) {
        self.properties.insert(SwitchProperties::OVERRIDE);
    }

    pub fn is_override(&self) -> bool {
        self.properties.contains(SwitchProperties::OVERRIDE)
    }

    pub fn is_truncated(&self) -> bool {
        self.properties.contains(SwitchProperties::TRUNCATED)
    }

    pub fn has_default(&self) -> bool {
        self.default.is_some()
    }

    pub fn targets(&self) -> impl Iterator<Item = &AddressWithContext> + '_ {
        self.cases
            .iter()
            .map(SwitchCase::target)
            .chain(self.default.iter().map(SwitchCase::target))
    }

    pub fn derived_references(&self) -> impl Iterator<Item = Reference> + '_ {
        let branch = self.branch;
        let flow = self.targets().map(move |target| {
            Reference::flow(
                branch,
                target.address(),
                ReferenceProperties::JUMP | ReferenceProperties::COMPUTED,
            )
            .with_origin(ReferenceOrigin::Derived)
        });
        let data = self.model.data_tables().map(move |table| {
            Reference::data(
                branch,
                table.address(),
                ReferenceProperties::READ | ReferenceProperties::INDIRECT,
            )
            .with_origin(ReferenceOrigin::Derived)
        });
        flow.chain(data)
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub enum SwitchModel {
    Absolute(AddressTable),
    #[default]
    Explicit,
    InlineBranchTable(AddressTable),
    OffsetRelative {
        table: AddressTable,
        base: RawAddress,
        signed: bool,
    },
    TwoLevel {
        outer: AddressTable,
        inner: AddressTable,
    },
}

impl SwitchModel {
    pub fn table(&self) -> Option<&AddressTable> {
        self.tables().next()
    }

    pub fn tables(&self) -> impl Iterator<Item = &AddressTable> + '_ {
        let (first, second) = match self {
            Self::Absolute(table)
            | Self::OffsetRelative { table, .. }
            | Self::InlineBranchTable(table) => (Some(table), None),
            Self::TwoLevel { outer, inner } => (Some(outer), Some(inner)),
            Self::Explicit => (None, None),
        };
        first.into_iter().chain(second)
    }

    pub fn data_tables(&self) -> impl Iterator<Item = &AddressTable> + '_ {
        let (first, second) = match self {
            Self::Absolute(table) | Self::OffsetRelative { table, .. } => (Some(table), None),
            Self::TwoLevel { outer, inner } => (Some(outer), Some(inner)),
            Self::Explicit | Self::InlineBranchTable(_) => (None, None),
        };
        first.into_iter().chain(second)
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct SwitchCaseLabel(u64);

impl SwitchCaseLabel {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn signed_value(&self) -> i64 {
        self.0 as i64
    }
}

impl From<u64> for SwitchCaseLabel {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct SwitchCase {
    target: AddressWithContext,
    labels: SmallVec<[SwitchCaseLabel; 1]>,
}

impl SwitchCase {
    pub fn new(target: AddressWithContext) -> Self {
        Self {
            target,
            labels: SmallVec::new(),
        }
    }

    pub fn target(&self) -> &AddressWithContext {
        &self.target
    }

    pub fn labels(&self) -> &[SwitchCaseLabel] {
        &self.labels
    }

    pub fn add_label(&mut self, label: SwitchCaseLabel) {
        self.labels.push(label);
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SwitchProperties: u32 {
        const CONTIGUOUS_ENTRIES    = 0x0000_0001;
        const GUARD_FOUND           = 0x0000_0002;
        const OVERRIDE              = 0x0000_0004;
        const TABLE_IN_READ_ONLY    = 0x0000_0008;
        const TARGETS_ALIGNED       = 0x0000_0010;
        const TARGETS_IN_EXECUTABLE = 0x0000_0020;
        const TRUNCATED             = 0x0000_0040;
    }
}

impl SwitchProperties {
    pub(crate) fn from_recovery(guarded: bool, truncated: bool) -> Self {
        let mut properties = Self::TARGETS_IN_EXECUTABLE;
        properties.set(Self::GUARD_FOUND, guarded);
        properties.set(Self::TRUNCATED, truncated);
        properties
    }

    pub(crate) fn confidence(self) -> Confidence {
        if self.contains(Self::GUARD_FOUND) && !self.contains(Self::TRUNCATED) {
            Confidence::somewhat_certain()
        } else {
            Confidence::uncertain()
        }
    }
}

archived_bitflags!(SwitchProperties, ArchivedSwitchProperties, u32);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn case_label_exposes_signed_interpretation() {
        let label = SwitchCaseLabel::new(u64::MAX);
        assert_eq!(label.value(), u64::MAX);
        assert_eq!(label.signed_value(), -1);
    }

    #[test]
    fn switch_properties_deserialise_ignore_unknown_bits() {
        let known = SwitchProperties::GUARD_FOUND | SwitchProperties::OVERRIDE;
        let mut bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&known)
            .expect("switch properties serialise")
            .to_vec();
        *bytes.last_mut().expect("archived u32 has bytes") |= 0x80;

        let decoded = rkyv::from_bytes::<SwitchProperties, rkyv::rancor::Error>(&bytes)
            .expect("switch properties deserialise");
        assert_eq!(decoded, known);
    }

    #[test]
    fn derived_references_cover_every_table() {
        use crate::storage::AddressSpaceId;

        let space = AddressSpaceId::new(1);
        let branch = Address::new(space, 0x1000u64);
        let outer = AddressTable::new(Address::new(space, 0x4000u64), 4).with_element_count(3);
        let inner = AddressTable::new(Address::new(space, 0x5000u64), 4).with_element_count(3);
        let switch = Switch::new(
            SwitchId::default(),
            branch,
            SwitchModel::TwoLevel { outer, inner },
        );

        let mut table_targets = switch
            .derived_references()
            .filter(|reference| reference.is_data())
            .filter_map(|reference| reference.target().address())
            .collect::<Vec<_>>();
        table_targets.sort();

        assert_eq!(
            table_targets,
            vec![
                Address::new(space, 0x4000u64),
                Address::new(space, 0x5000u64),
            ]
        );
    }
}
