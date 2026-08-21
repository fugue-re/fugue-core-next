use crate::ir::{Address, AddressRange, AddressRangeSet, Id};
use crate::storage::AddressSpaceId;
use crate::storage::entities::schema::{ENTITY_KEY_PROBLEM_ID, ENTITY_PROBLEM_ID};
use crate::storage::entities::{Entity, EntityId, EntityKey, EntityKeyId, MutableEntity};
use crate::types::Revision;

mod table;
pub(crate) use table::{ATTRIBUTE_PROBLEM_CACHE_SIZE, DEFAULT_PROBLEM_CACHE_BYTES};
pub use table::{ProblemRef, ProblemTable, ProblemTableError};

pub type ProblemId = Id<Problem>;

impl EntityKey for ProblemId {
    const ID: EntityKeyId = ENTITY_KEY_PROBLEM_ID;
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
    #[default]
    Unknown,
    WorkCausesMerged,
}

impl ProblemKind {
    pub(crate) const MIN: Self = Self::AnalysisCoverageInvalidated;
    pub(crate) const MAX: Self = Self::WorkCausesMerged;

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
    Address(Address),
    AddressSpace(AddressSpaceId),
    #[default]
    Global,
    Range(AddressRange),
}

impl ProblemScope {
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
    attempt_count: u8,
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
            attempt_count: 1,
            first_seen: observed_revision,
            last_seen: observed_revision,
        }
    }

    pub fn with_id(mut self, id: ProblemId) -> Self {
        self.set_id(id);
        self
    }

    pub(crate) fn set_id(&mut self, id: ProblemId) {
        self.id = id;
    }

    pub fn id(&self) -> ProblemId {
        self.id
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

    pub fn observed_revision(&self) -> Revision {
        self.observed_revision
    }

    pub fn attempt_count(&self) -> u8 {
        self.attempt_count
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

    pub fn key(&self) -> ProblemKey {
        ProblemKey::scoped(self.scope, self.kind)
    }

    pub fn record_attempt(&mut self, observed_revision: Revision) {
        self.attempt_count = self.attempt_count.saturating_add(1);
        self.last_seen = observed_revision;
    }
}
