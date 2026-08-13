use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::mem;

use smallvec::SmallVec;
use smol_str::SmolStr;

use crate::ir::{Address, AddressRange, AddressRangeSet};
use crate::storage::entities::schema::ENTITY_COVERAGE_ID;
use crate::storage::entities::{Entity, EntityId, ProjectEntity};
use crate::storage::project::PersistableProjectEntity;
use crate::storage::{EntityStorage, EntityStorageError};

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[repr(u8)]
pub enum AnalysisPhase {
    #[default]
    Decode = 1,
    Derive = 3,
    Identify = 5,
    Partition = 2,
    Propagate = 4,
    Retract = 0,
}

impl AnalysisPhase {
    pub const ALL: [AnalysisPhase; 6] = [
        AnalysisPhase::Retract,
        AnalysisPhase::Decode,
        AnalysisPhase::Partition,
        AnalysisPhase::Derive,
        AnalysisPhase::Propagate,
        AnalysisPhase::Identify,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Derive => "derive",
            Self::Identify => "identify",
            Self::Partition => "partition",
            Self::Propagate => "propagate",
            Self::Retract => "retract",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Retract => 0,
            Self::Decode => 1,
            Self::Partition => 2,
            Self::Derive => 3,
            Self::Propagate => 4,
            Self::Identify => 5,
        }
    }
}

impl Ord for AnalysisPhase {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for AnalysisPhase {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for AnalysisPhase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalysisCoverage {
    analysers: BTreeMap<SmolStr, AnalyserCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnalyserCoverage {
    pending: AddressRangeSet,
    phase: AnalysisPhase,
    ranges: AddressRangeSet,
}

enum CoverageConfigurationChange {
    Added {
        name: SmolStr,
        phase: AnalysisPhase,
        ranges: AddressRangeSet,
    },
    PhaseChanged {
        name: SmolStr,
        previous: AnalysisPhase,
        current: AnalysisPhase,
        ranges: AddressRangeSet,
        target_ranges: AddressRangeSet,
    },
    Removed {
        name: SmolStr,
        phase: AnalysisPhase,
        ranges: AddressRangeSet,
    },
}

pub(crate) struct CoverageConfiguration {
    reconfiguration: CoverageReconfiguration,
}

pub(crate) struct CoverageReanalysis {
    analyser: SmolStr,
    regions: AddressRangeSet,
}

impl CoverageReanalysis {
    pub(crate) fn analyser(&self) -> &str {
        &self.analyser
    }

    pub(crate) fn regions(&self) -> &AddressRangeSet {
        &self.regions
    }
}

pub(crate) struct CoverageReconfiguration {
    analysers: SmallVec<[SmolStr; 4]>,
    invalidated: AddressRangeSet,
    reanalysis: SmallVec<[CoverageReanalysis; 4]>,
}

impl CoverageReconfiguration {
    pub(crate) fn analysers(&self) -> &[SmolStr] {
        &self.analysers
    }

    pub(crate) fn invalidated(&self) -> &AddressRangeSet {
        &self.invalidated
    }

    pub(crate) fn reanalysis(&self) -> &[CoverageReanalysis] {
        &self.reanalysis
    }
}

impl CoverageConfiguration {
    pub(crate) fn into_reconfiguration(self) -> CoverageReconfiguration {
        self.reconfiguration
    }

    fn from_changes(
        changes: SmallVec<[CoverageConfigurationChange; 4]>,
    ) -> CoverageReconfiguration {
        struct Replacement {
            phase: AnalysisPhase,
            regions: AddressRangeSet,
        }

        let mut analysers = SmallVec::new();
        let mut invalidated = AddressRangeSet::new();
        let mut replacements = BTreeMap::<SmolStr, Replacement>::new();

        for change in &changes {
            match change {
                CoverageConfigurationChange::Added {
                    name,
                    phase,
                    ranges,
                } => {
                    replacements
                        .entry(name.clone())
                        .or_insert_with(|| Replacement {
                            phase: *phase,
                            regions: ranges.clone(),
                        });
                }
                CoverageConfigurationChange::PhaseChanged {
                    name,
                    current,
                    target_ranges,
                    ..
                } => {
                    replacements
                        .entry(name.clone())
                        .or_insert_with(|| Replacement {
                            phase: *current,
                            regions: target_ranges.clone(),
                        });
                }
                CoverageConfigurationChange::Removed { .. } => {}
            }
        }

        for change in changes {
            match change {
                CoverageConfigurationChange::Added { name, ranges, .. } => {
                    if !ranges.is_empty() {
                        analysers.push(name);
                        for range in ranges.ranges() {
                            invalidated.insert_range(range);
                        }
                    }
                }
                CoverageConfigurationChange::PhaseChanged {
                    name,
                    previous,
                    ranges,
                    target_ranges,
                    ..
                } => {
                    analysers.push(name.clone());
                    for range in ranges.ranges().chain(target_ranges.ranges()) {
                        invalidated.insert_range(range);
                    }
                    for range in ranges.ranges() {
                        if let Some(replacement) = replacements.get_mut(&name) {
                            replacement.regions.insert_range(range);
                        }
                        for replacement in replacements.values_mut() {
                            if replacement.phase == previous {
                                replacement.regions.insert_range(range);
                            }
                        }
                    }
                }
                CoverageConfigurationChange::Removed {
                    name,
                    phase,
                    ranges,
                } => {
                    analysers.push(name);
                    for range in ranges.ranges() {
                        invalidated.insert_range(range);
                        for replacement in replacements.values_mut() {
                            if replacement.phase == phase {
                                replacement.regions.insert_range(range);
                            }
                        }
                    }
                }
            }
        }

        let reanalysis = replacements
            .into_iter()
            .filter_map(|(analyser, replacement)| {
                (!replacement.regions.is_empty()).then_some(CoverageReanalysis {
                    analyser,
                    regions: replacement.regions,
                })
            })
            .collect();

        CoverageReconfiguration {
            analysers,
            invalidated,
            reanalysis,
        }
    }
}

#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AnalysisCoverageRecord {
    analysers: Vec<AnalyserCoverageRecord>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AnalyserCoverageRecord {
    name: String,
    pending: Vec<AddressRange>,
    phase: AnalysisPhase,
    ranges: Vec<AddressRange>,
}

impl Entity for AnalysisCoverageRecord {
    const ID: EntityId = ENTITY_COVERAGE_ID;
}

impl AnalysisCoverage {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn configure<'a>(
        &mut self,
        analysers: impl IntoIterator<Item = (&'a str, AnalysisPhase)>,
    ) -> CoverageConfiguration {
        let previous_phase_coverage = AnalysisPhase::ALL
            .into_iter()
            .map(|phase| (phase, self.covered(phase)))
            .collect::<BTreeMap<_, _>>();
        let mut configured = analysers
            .into_iter()
            .map(|(name, phase)| (SmolStr::new(name), phase))
            .collect::<BTreeMap<_, _>>();

        let mut changes = SmallVec::new();
        let previous = mem::take(&mut self.analysers);
        for (name, coverage) in previous {
            match configured.remove(&name) {
                Some(phase) if phase == coverage.phase => {
                    self.analysers.insert(name, coverage);
                }
                Some(phase) => {
                    let pending = coverage.pending;
                    changes.push(CoverageConfigurationChange::PhaseChanged {
                        name: name.clone(),
                        previous: coverage.phase,
                        current: phase,
                        ranges: coverage.ranges,
                        target_ranges: previous_phase_coverage
                            .get(&phase)
                            .cloned()
                            .unwrap_or_default(),
                    });
                    self.analysers.insert(
                        name,
                        AnalyserCoverage {
                            pending,
                            phase,
                            ranges: AddressRangeSet::new(),
                        },
                    );
                }
                None => changes.push(CoverageConfigurationChange::Removed {
                    name,
                    phase: coverage.phase,
                    ranges: coverage.ranges,
                }),
            }
        }

        for (name, phase) in configured {
            changes.push(CoverageConfigurationChange::Added {
                name: name.clone(),
                phase,
                ranges: previous_phase_coverage
                    .get(&phase)
                    .cloned()
                    .unwrap_or_default(),
            });
            self.analysers.insert(
                name,
                AnalyserCoverage {
                    pending: AddressRangeSet::new(),
                    phase,
                    ranges: AddressRangeSet::new(),
                },
            );
        }

        let mut reconfiguration = CoverageConfiguration::from_changes(changes);
        for reanalysis in &reconfiguration.reanalysis {
            let coverage = self
                .analysers
                .get_mut(&reanalysis.analyser)
                .expect("reanalysis must name a configured analyser");
            for range in reanalysis.regions.ranges() {
                coverage.pending.insert_range(range);
            }
        }
        reconfiguration.reanalysis = self
            .analysers
            .iter()
            .filter(|(_, coverage)| !coverage.pending.is_empty())
            .map(|(name, coverage)| CoverageReanalysis {
                analyser: name.clone(),
                regions: coverage.pending.clone(),
            })
            .collect();

        CoverageConfiguration { reconfiguration }
    }

    pub fn mark(&mut self, analyser: &str, phase: AnalysisPhase, range: AddressRange) {
        self.analysers
            .entry(SmolStr::new(analyser))
            .and_modify(|coverage| {
                coverage.pending.remove_range(range);
                coverage.phase = phase;
                coverage.ranges.insert_range(range);
            })
            .or_insert_with(|| {
                let mut ranges = AddressRangeSet::new();
                ranges.insert_range(range);
                AnalyserCoverage {
                    pending: AddressRangeSet::new(),
                    phase,
                    ranges,
                }
            });
    }

    pub(crate) fn clear(&mut self, range: AddressRange) {
        let mut invalidated_region = AddressRangeSet::new();
        invalidated_region.insert_range(range);
        for coverage in self.analysers.values_mut() {
            for invalidated in coverage.ranges.intersection(&invalidated_region).ranges() {
                coverage.pending.insert_range(invalidated);
            }
            coverage.ranges.remove_range(range);
        }
    }

    pub fn range_count(&self) -> usize {
        self.analysers
            .values()
            .map(|coverage| coverage.ranges.range_count())
            .sum()
    }

    pub fn covered(&self, phase: AnalysisPhase) -> AddressRangeSet {
        let mut ranges = self
            .analysers
            .values()
            .filter(|coverage| coverage.phase == phase)
            .map(|coverage| &coverage.ranges);
        let Some(first) = ranges.next() else {
            return AddressRangeSet::new();
        };

        ranges.fold(first.clone(), |covered, ranges| {
            covered.intersection(ranges)
        })
    }

    pub fn is_covered(&self, phase: AnalysisPhase, address: Address) -> bool {
        self.covered(phase).contains(address)
    }

    pub fn gaps(&self, phase: AnalysisPhase, within: &AddressRangeSet) -> AddressRangeSet {
        within.difference(&self.covered(phase))
    }

    pub(crate) fn gaps_for(&self, analyser: &str, within: &AddressRangeSet) -> AddressRangeSet {
        self.analysers.get(analyser).map_or_else(
            || within.clone(),
            |coverage| within.difference(&coverage.ranges),
        )
    }

    pub fn is_complete(&self, phase: AnalysisPhase, within: &AddressRangeSet) -> bool {
        self.gaps(phase, within).is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.analysers
            .values()
            .all(|coverage| coverage.ranges.is_empty())
    }

    pub(crate) fn from_storage(storage: &EntityStorage) -> Result<Self, EntityStorageError> {
        let Some(record) =
            storage.get::<ProjectEntity, AnalysisCoverageRecord>(&ProjectEntity::Coverage)?
        else {
            return Ok(Self::new());
        };

        let mut coverage = Self::new();
        for analyser in record.analysers {
            let mut ranges = AddressRangeSet::new();
            for range in analyser.ranges {
                ranges.insert_range(range);
            }
            let mut pending = AddressRangeSet::new();
            for range in analyser.pending {
                pending.insert_range(range);
            }
            coverage.analysers.insert(
                SmolStr::new(analyser.name),
                AnalyserCoverage {
                    pending,
                    phase: analyser.phase,
                    ranges,
                },
            );
        }

        Ok(coverage)
    }
}

impl PersistableProjectEntity for AnalysisCoverage {
    fn persist(&self, storage: &EntityStorage) -> Result<(), EntityStorageError> {
        storage.insert(
            &ProjectEntity::Coverage,
            &AnalysisCoverageRecord {
                analysers: self
                    .analysers
                    .iter()
                    .map(|(name, coverage)| AnalyserCoverageRecord {
                        name: name.to_string(),
                        pending: coverage.pending.ranges().collect(),
                        phase: coverage.phase,
                        ranges: coverage.ranges.ranges().collect(),
                    })
                    .collect(),
            },
        )
    }
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use super::*;
    #[cfg(any(feature = "mdbx", feature = "rocksdb"))]
    use crate::loader::Shellcode;
    #[cfg(feature = "sqlite")]
    use crate::storage::TRANSIENT;
    #[cfg(any(feature = "mdbx", feature = "rocksdb"))]
    use crate::storage::entities::EntityStorageProviderFromLoadable;
    use crate::storage::entities::InMemoryEntityStorage;
    #[cfg(feature = "mdbx")]
    use crate::storage::entities::MdbxEntityStorage;
    #[cfg(feature = "rocksdb")]
    use crate::storage::entities::RocksDbEntityStorage;
    #[cfg(feature = "sqlite")]
    use crate::storage::entities::SqliteEntityStorage;
    use crate::storage::segments::DEFAULT_SPACE_ID;
    #[cfg(any(feature = "mdbx", feature = "rocksdb"))]
    use crate::types::AttributeMap;
    #[cfg(any(feature = "mdbx", feature = "rocksdb"))]
    use crate::types::attributes::ATTRIBUTE_PROJECT_PATH;

    fn range(start: u64, end: u64) -> AddressRange {
        AddressRange::new(DEFAULT_SPACE_ID, start.into(), end.into())
    }

    fn assert_coverage_round_trip(storage: EntityStorage) -> Result<(), EntityStorageError> {
        let mut expected = AnalysisCoverage::new();
        expected.configure([
            ("decoder", AnalysisPhase::Decode),
            ("partitioner", AnalysisPhase::Partition),
        ]);
        expected.mark("decoder", AnalysisPhase::Decode, range(0x1000, 0x1fff));
        expected.mark(
            "partitioner",
            AnalysisPhase::Partition,
            range(0x2000, 0x2fff),
        );
        expected.clear(range(0x1800, 0x18ff));
        expected.persist(&storage)?;

        assert_eq!(AnalysisCoverage::from_storage(&storage)?, expected);
        Ok(())
    }

    #[test]
    fn gaps_exclude_covered_ranges() {
        let mut coverage = AnalysisCoverage::new();
        coverage.configure([("decoder", AnalysisPhase::Decode)]);
        coverage.mark("decoder", AnalysisPhase::Decode, range(0x1000, 0x100f));

        let mut within = AddressRangeSet::new();
        within.insert_range(range(0x1000, 0x101f));
        let gaps = coverage.gaps(AnalysisPhase::Decode, &within);

        assert!(!gaps.contains(Address::from(0x1000u64)));
        assert!(gaps.contains(Address::from(0x1018u64)));
    }

    #[test]
    fn phase_coverage_requires_every_configured_analyser() {
        let mut coverage = AnalysisCoverage::new();
        coverage.configure([
            ("first", AnalysisPhase::Decode),
            ("second", AnalysisPhase::Decode),
        ]);
        let range = range(0x1000, 0x100f);

        coverage.mark("first", AnalysisPhase::Decode, range);
        assert!(!coverage.is_covered(AnalysisPhase::Decode, Address::from(0x1000u64)));

        coverage.mark("second", AnalysisPhase::Decode, range);
        assert!(coverage.is_covered(AnalysisPhase::Decode, Address::from(0x1000u64)));
    }

    #[test]
    fn coverage_round_trips_on_enabled_entity_backends() -> Result<(), Box<dyn Error>> {
        assert_coverage_round_trip(EntityStorage::new(InMemoryEntityStorage::new()))?;

        #[cfg(feature = "sqlite")]
        assert_coverage_round_trip(EntityStorage::new(SqliteEntityStorage::<TRANSIENT>::new()?))?;

        #[cfg(any(feature = "mdbx", feature = "rocksdb"))]
        let loader = Shellcode::new("x86:LE:64", 0u64, &[0u8])?;

        #[cfg(feature = "rocksdb")]
        {
            let directory = tempfile::tempdir()?;
            let mut attributes = AttributeMap::new();
            attributes.set_attr(ATTRIBUTE_PROJECT_PATH, directory.path().to_path_buf());
            let provider = RocksDbEntityStorage::from_loadable(&loader, &mut attributes)?;
            assert_coverage_round_trip(EntityStorage::new(provider))?;
        }

        #[cfg(feature = "mdbx")]
        {
            let directory = tempfile::tempdir()?;
            let mut attributes = AttributeMap::new();
            attributes.set_attr(ATTRIBUTE_PROJECT_PATH, directory.path().to_path_buf());
            let provider = MdbxEntityStorage::from_loadable(&loader, &mut attributes)?;
            assert_coverage_round_trip(EntityStorage::new(provider))?;
        }

        Ok(())
    }

    #[test]
    fn rename_reports_invalidation_and_records_replacement() {
        let mut coverage = AnalysisCoverage::new();
        coverage.configure([("old-name", AnalysisPhase::Decode)]);
        coverage.mark("old-name", AnalysisPhase::Decode, range(0x1000, 0x1fff));

        let reconfiguration = coverage
            .configure([("new-name", AnalysisPhase::Decode)])
            .into_reconfiguration();

        assert_eq!(reconfiguration.analysers(), ["old-name", "new-name"]);
        assert_eq!(reconfiguration.reanalysis().len(), 1);
        assert_eq!(reconfiguration.reanalysis()[0].analyser(), "new-name");
        assert!(
            reconfiguration.reanalysis()[0]
                .regions()
                .contains(Address::from(0x1800u64))
        );
        assert!(coverage.covered(AnalysisPhase::Decode).is_empty());
    }

    #[test]
    fn added_analyser_reprocesses_previously_complete_phase_coverage() {
        let mut coverage = AnalysisCoverage::new();
        coverage.configure([("existing", AnalysisPhase::Decode)]);
        coverage.mark("existing", AnalysisPhase::Decode, range(0x1000, 0x1fff));

        let reconfiguration = coverage
            .configure([
                ("existing", AnalysisPhase::Decode),
                ("added", AnalysisPhase::Decode),
            ])
            .into_reconfiguration();

        assert_eq!(reconfiguration.analysers(), ["added"]);
        assert_eq!(reconfiguration.reanalysis().len(), 1);
        assert_eq!(reconfiguration.reanalysis()[0].analyser(), "added");
        assert!(
            reconfiguration.reanalysis()[0]
                .regions()
                .contains(Address::from(0x1800u64))
        );
        assert!(
            reconfiguration
                .invalidated()
                .contains(Address::from(0x1800u64))
        );
        assert!(coverage.covered(AnalysisPhase::Decode).is_empty());
    }

    #[test]
    fn pending_reanalysis_survives_reopen_until_marked() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut coverage = AnalysisCoverage::new();
        coverage.configure([("existing", AnalysisPhase::Decode)]);
        coverage.mark("existing", AnalysisPhase::Decode, range(0x1000, 0x1fff));
        coverage.configure([
            ("existing", AnalysisPhase::Decode),
            ("added", AnalysisPhase::Decode),
        ]);
        coverage.persist(&storage)?;

        let mut reopened = AnalysisCoverage::from_storage(&storage)?;
        let reconfiguration = reopened
            .configure([
                ("existing", AnalysisPhase::Decode),
                ("added", AnalysisPhase::Decode),
            ])
            .into_reconfiguration();

        assert_eq!(reconfiguration.reanalysis().len(), 1);
        assert_eq!(reconfiguration.reanalysis()[0].analyser(), "added");
        assert!(
            reconfiguration.reanalysis()[0]
                .regions()
                .contains(Address::from(0x1800u64))
        );

        reopened.mark("added", AnalysisPhase::Decode, range(0x1000, 0x1fff));
        assert!(
            reopened
                .configure([
                    ("existing", AnalysisPhase::Decode),
                    ("added", AnalysisPhase::Decode),
                ])
                .into_reconfiguration()
                .reanalysis()
                .is_empty(),
            "successfully processed coverage must clear its durable reanalysis marker"
        );

        Ok(())
    }

    #[test]
    fn invalidated_coverage_is_a_durable_reanalysis_marker() -> Result<(), EntityStorageError> {
        let storage = EntityStorage::new(InMemoryEntityStorage::new());
        let mut coverage = AnalysisCoverage::new();
        coverage.configure([("decoder", AnalysisPhase::Decode)]);
        coverage.mark("decoder", AnalysisPhase::Decode, range(0x1000, 0x1fff));
        coverage.clear(range(0x1800, 0x18ff));
        coverage.persist(&storage)?;

        let mut reopened = AnalysisCoverage::from_storage(&storage)?;
        let reconfiguration = reopened
            .configure([("decoder", AnalysisPhase::Decode)])
            .into_reconfiguration();

        assert_eq!(reconfiguration.reanalysis().len(), 1);
        assert_eq!(reconfiguration.reanalysis()[0].analyser(), "decoder");
        assert_eq!(reconfiguration.reanalysis()[0].regions(), &{
            let mut ranges = AddressRangeSet::new();
            ranges.insert_range(range(0x1800, 0x18ff));
            ranges
        });

        Ok(())
    }
}
