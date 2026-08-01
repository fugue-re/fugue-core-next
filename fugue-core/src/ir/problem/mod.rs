use crate::engine::change::ChangeKinds;
use crate::ir::{Address, AddressRange, AddressRangeSet, Id};
use crate::storage::AddressSpaceId;
use crate::storage::entities::schema::ENTITY_PROBLEM_ID;
use crate::storage::entities::{Entity, EntityId, MutableEntity};
use crate::types::Revision;

mod table;
pub use table::{ProblemRef, ProblemTable, ProblemTableError};

pub type ProblemId = Id<Problem>;

#[derive(
    Debug,
    Clone,
    Copy,
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
#[allow(unknown_lints, sorted_enum_variants)]
pub enum ProblemKind {
    AnalysisCoverageInvalidated,
    AvoidedBytes,
    CannotCreateFunction,
    ChangeIndexCollapsed,
    DecodeFailed,
    FunctionTooLarge,
    HinderedByAssertedFact,
    PassFailed,
    PendingWorkCollapsed,
    ReadSetCollapsed,
    RetryBudgetExhausted,
    SwitchBoundExceeded,
    SwitchUnresolved,
    WorkCausesMerged,
    #[default]
    Unknown,
}

impl ProblemKind {
    pub(crate) const MIN: Self = Self::AnalysisCoverageInvalidated;
    pub(crate) const MAX: Self = Self::Unknown;

    pub fn class(self) -> ProblemClass {
        match self {
            Self::AnalysisCoverageInvalidated
            | Self::ChangeIndexCollapsed
            | Self::PendingWorkCollapsed
            | Self::ReadSetCollapsed
            | Self::RetryBudgetExhausted
            | Self::WorkCausesMerged => ProblemClass::Operational,
            _ => ProblemClass::Semantic,
        }
    }

    pub(crate) fn input_kinds(self) -> ChangeKinds {
        let recovery = ChangeKinds::BYTES_WRITTEN
            | ChangeKinds::FUNCTIONS
            | ChangeKinds::SEGMENTS
            | ChangeKinds::SYMBOLS;
        match self {
            Self::AvoidedBytes => ChangeKinds::BYTES_WRITTEN | ChangeKinds::SEGMENTS,
            Self::CannotCreateFunction
            | Self::DecodeFailed
            | Self::FunctionTooLarge
            | Self::PassFailed => recovery,
            Self::HinderedByAssertedFact => ChangeKinds::FUNCTIONS,
            Self::SwitchBoundExceeded | Self::SwitchUnresolved => {
                ChangeKinds::BYTES_WRITTEN
                    | ChangeKinds::FUNCTIONS
                    | ChangeKinds::SEGMENTS
                    | ChangeKinds::SWITCHES
            }
            Self::Unknown => ChangeKinds::all().difference(ChangeKinds::PROBLEMS),
            Self::AnalysisCoverageInvalidated
            | Self::ChangeIndexCollapsed
            | Self::PendingWorkCollapsed
            | Self::ReadSetCollapsed
            | Self::RetryBudgetExhausted
            | Self::WorkCausesMerged => ChangeKinds::empty(),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum ProblemClass {
    Operational,
    Semantic,
}

#[derive(
    Debug,
    Clone,
    Copy,
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
pub enum ProblemScope {
    #[default]
    Global,
    AddressSpace(AddressSpaceId),
    Address(Address),
    Range(AddressRange),
}

impl ProblemScope {
    pub fn address(self) -> Option<Address> {
        match self {
            Self::Address(address) => Some(address),
            Self::Global | Self::AddressSpace(_) | Self::Range(_) => None,
        }
    }

    pub fn range(self) -> Option<AddressRange> {
        match self {
            Self::Address(address) => Some(AddressRange::point(address)),
            Self::Range(range) => Some(range),
            Self::Global | Self::AddressSpace(_) => None,
        }
    }

    pub(crate) fn for_regions(regions: &AddressRangeSet) -> Self {
        let mut ranges = regions.ranges();
        let Some(first) = ranges.next() else {
            return Self::Global;
        };
        let Some(second) = ranges.next() else {
            return Self::Range(first);
        };
        let space = first.space();
        if second.space() != space || ranges.any(|range| range.space() != space) {
            Self::Global
        } else {
            Self::AddressSpace(space)
        }
    }

    pub(crate) fn covering(self, other: Self) -> Self {
        if self == other {
            return self;
        }

        let space = |scope| match scope {
            Self::AddressSpace(space) => Some(space),
            Self::Address(address) => Some(address.space()),
            Self::Range(range) => Some(range.space()),
            Self::Global => None,
        };

        match (space(self), space(other)) {
            (Some(left), Some(right)) if left == right => Self::AddressSpace(left),
            _ => Self::Global,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProblemKey {
    scope: ProblemScope,
    kind: ProblemKind,
}

impl ProblemKey {
    pub fn new(address: Address, kind: ProblemKind) -> Self {
        Self::scoped(ProblemScope::Address(address), kind)
    }

    pub fn scoped(scope: ProblemScope, kind: ProblemKind) -> Self {
        Self { scope, kind }
    }

    pub fn scope(&self) -> ProblemScope {
        self.scope
    }

    pub fn address(&self) -> Option<Address> {
        self.scope.address()
    }

    pub fn kind(&self) -> ProblemKind {
        self.kind
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct Problem {
    id: ProblemId,
    scope: ProblemScope,
    kind: ProblemKind,
    observed_revision: Revision,
    attempts: u8,
    first_seen: Revision,
    last_seen: Revision,
}

impl AsRef<Problem> for Problem {
    fn as_ref(&self) -> &Problem {
        self
    }
}

impl AsMut<Problem> for Problem {
    fn as_mut(&mut self) -> &mut Problem {
        self
    }
}

impl Entity for Problem {
    const ID: EntityId = ENTITY_PROBLEM_ID;
}

impl MutableEntity for Problem {
    type Key = ProblemId;

    fn entity_key(&self) -> ProblemId {
        self.id
    }
}

impl Problem {
    pub fn new(
        id: ProblemId,
        address: Address,
        kind: ProblemKind,
        observed_revision: Revision,
    ) -> Self {
        Self::new_scoped(id, ProblemScope::Address(address), kind, observed_revision)
    }

    pub fn with_id(mut self, id: ProblemId) -> Self {
        self.id = id;
        self
    }

    pub fn id(&self) -> ProblemId {
        self.id
    }

    pub fn new_scoped(
        id: ProblemId,
        scope: ProblemScope,
        kind: ProblemKind,
        observed_revision: Revision,
    ) -> Self {
        Self {
            id,
            scope,
            kind,
            observed_revision,
            attempts: 1,
            first_seen: observed_revision,
            last_seen: observed_revision,
        }
    }

    pub fn scope(&self) -> ProblemScope {
        self.scope
    }

    pub fn address(&self) -> Option<Address> {
        self.scope.address()
    }

    pub fn key(&self) -> ProblemKey {
        ProblemKey::scoped(self.scope, self.kind)
    }

    pub fn kind(&self) -> ProblemKind {
        self.kind
    }

    pub fn observed_revision(&self) -> Revision {
        self.observed_revision
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn first_seen(&self) -> Revision {
        self.first_seen
    }

    pub fn last_seen(&self) -> Revision {
        self.last_seen
    }

    pub fn set_observed_revision(&mut self, observed_revision: Revision) {
        self.observed_revision = observed_revision;
    }

    pub fn set_last_seen(&mut self, last_seen: Revision) {
        self.last_seen = last_seen;
    }

    pub fn record_attempt(&mut self, observed_revision: Revision) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_seen = observed_revision;
    }
}
