#[cfg(any(feature = "mdbx", feature = "rocksdb", feature = "sqlite"))]
use std::error::Error;
#[cfg(not(any(feature = "mdbx", feature = "rocksdb", feature = "sqlite")))]
use std::process;

#[cfg(any(feature = "mdbx", feature = "rocksdb", feature = "sqlite"))]
mod benchmark {
    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::time::Instant;
    use std::{env, fs};

    use fugue_core::attributes;
    use fugue_core::engine::{AnalysisEngine, AnalysisEngineConfig};
    use fugue_core::loader::{Loadable, Loader};
    use fugue_core::project::Project;
    use fugue_core::storage::{
        DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage, EntityStorage,
        InMemoryEntityStorage, MemoryMappedSegmentStorage, PersistentEntityStorageProvider,
        PersistentStorageProvider, SegmentStorage, StorageContainer, StorageProvider,
        StorageProviderError, TRANSIENT, TransientStorageProvider,
    };
    use fugue_core::types::{ATTRIBUTE_PROJECT_PATH, AttributeMap};

    type PersistentMemoryMappedStorageProvider =
        PersistentStorageProvider<DefaultPersistentEntityStorage, DefaultPersistentSegmentStorage>;

    struct MemoryMappedTransientStorageProvider;

    impl StorageProvider for MemoryMappedTransientStorageProvider {
        fn from_loadable(
            loadable: &impl Loadable,
            attributes: &mut AttributeMap,
        ) -> Result<StorageContainer, StorageProviderError> {
            let entities = EntityStorage::new(InMemoryEntityStorage::new());
            let (segments, image_resolution) = SegmentStorage::from_loadable::<
                MemoryMappedSegmentStorage<{ TRANSIENT }>,
            >(loadable, attributes)?
            .into_parts();

            Ok(StorageContainer::from_parts(entities, segments)?
                .with_image_resolution(image_resolution))
        }

        fn from_storage(
            _path: impl AsRef<Path>,
            _attributes: &mut AttributeMap,
        ) -> Result<StorageContainer, StorageProviderError> {
            Err(StorageProviderError::NotAStandaloneProject)
        }
    }

    #[derive(Clone, Copy)]
    enum StorageMode {
        Memory,
        MemoryMapped,
        PersistentEntities,
        Persistent,
        Reopen,
    }

    impl StorageMode {
        fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
            match value {
                "memory" => Ok(Self::Memory),
                "mmap" => Ok(Self::MemoryMapped),
                "entities" | "sqlite" => Ok(Self::PersistentEntities),
                "persistent" => Ok(Self::Persistent),
                "reopen" => Ok(Self::Reopen),
                _ => Err(format!("unknown storage mode `{value}`").into()),
            }
        }

        fn name(self) -> &'static str {
            match self {
                Self::Memory => "memory",
                Self::MemoryMapped => "mmap",
                Self::PersistentEntities => "entities",
                Self::Persistent => "persistent",
                Self::Reopen => "reopen",
            }
        }

        fn entity_backend(self) -> &'static str {
            match self {
                Self::Memory | Self::MemoryMapped => "memory",
                Self::PersistentEntities | Self::Persistent | Self::Reopen => {
                    persistent_entity_backend()
                }
            }
        }

        fn segment_backend(self) -> &'static str {
            match self {
                Self::Memory | Self::PersistentEntities => "memory",
                Self::MemoryMapped | Self::Persistent | Self::Reopen => "mmap",
            }
        }
    }

    #[cfg(feature = "sqlite")]
    fn persistent_entity_backend() -> &'static str {
        "sqlite"
    }

    #[cfg(all(feature = "rocksdb", not(feature = "sqlite")))]
    fn persistent_entity_backend() -> &'static str {
        "rocksdb"
    }

    #[cfg(all(feature = "mdbx", not(feature = "rocksdb"), not(feature = "sqlite")))]
    fn persistent_entity_backend() -> &'static str {
        "mdbx"
    }

    struct DiskUsage {
        allocated: u64,
        logical: u64,
    }

    struct ProjectCounts {
        blocks: usize,
        functions: usize,
        memberships: usize,
        problems: usize,
        switches: usize,
        symbols: usize,
    }

    impl DiskUsage {
        fn measure(path: &Path) -> Result<Self, Box<dyn Error>> {
            if !path.exists() {
                return Ok(Self {
                    allocated: 0,
                    logical: 0,
                });
            }

            let mut allocated = 0u64;
            let mut logical = 0u64;
            let mut pending = vec![path.to_path_buf()];
            while let Some(path) = pending.pop() {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    for entry in fs::read_dir(path)? {
                        pending.push(entry?.path());
                    }
                } else if metadata.is_file() {
                    logical = logical.saturating_add(metadata.len());
                    allocated = allocated.saturating_add(allocated_bytes(&metadata));
                }
            }

            Ok(Self { allocated, logical })
        }
    }

    #[cfg(unix)]
    fn allocated_bytes(metadata: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt as _;

        metadata.blocks().saturating_mul(512)
    }

    #[cfg(not(unix))]
    fn allocated_bytes(metadata: &fs::Metadata) -> u64 {
        metadata.len()
    }

    fn project_for(
        mode: StorageMode,
        loader: &Loader,
        project_path: &Path,
    ) -> Result<Project, Box<dyn Error>> {
        let attributes = attributes![ATTRIBUTE_PROJECT_PATH => project_path];
        match mode {
            StorageMode::Memory => Ok(Project::new_with_provider::<TransientStorageProvider>(
                loader, attributes,
            )?),
            StorageMode::MemoryMapped => Ok(Project::new_with_provider::<
                MemoryMappedTransientStorageProvider,
            >(loader, attributes)?),
            StorageMode::PersistentEntities => Ok(Project::new_with_provider::<
                PersistentEntityStorageProvider,
            >(loader, attributes)?),
            StorageMode::Persistent => Ok(Project::new_with_provider::<
                PersistentMemoryMappedStorageProvider,
            >(loader, attributes)?),
            StorageMode::Reopen => Err("reopen does not create a project from a loader".into()),
        }
    }

    fn reopened_project(project_path: &Path) -> Result<Project, Box<dyn Error>> {
        Ok(Project::from_file_with_provider::<
            PersistentMemoryMappedStorageProvider,
        >(project_path)?)
    }

    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        if env::var_os("RUST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init();
        }

        let mode = StorageMode::parse(
            &env::args()
                .nth(1)
                .ok_or("expected storage mode as the first argument")?,
        )?;
        let input = env::args()
            .nth(2)
            .map(PathBuf::from)
            .ok_or("expected input path as the second argument")?;
        let storage_root = env::args()
            .nth(3)
            .map(PathBuf::from)
            .ok_or("expected storage root as the third argument")?;
        let project_path = storage_root.join("project.fdbz");

        fs::create_dir_all(&storage_root)?;

        let load_start = Instant::now();
        let loader = match mode {
            StorageMode::Reopen => None,
            _ => Some(Loader::from_file(&input)?),
        };
        let load_elapsed = load_start.elapsed();

        let project_start = Instant::now();
        let project = match mode {
            StorageMode::Reopen => reopened_project(&project_path)?,
            _ => project_for(
                mode,
                loader.as_ref().ok_or("loader unavailable")?,
                &project_path,
            )?,
        };
        let project_elapsed = project_start.elapsed();

        let analysis_start = Instant::now();
        let config = AnalysisEngineConfig::default().with_worker_limit(1);
        let engine = AnalysisEngine::with_config(project, config)?;
        engine.analyse()?;
        let analysis_elapsed = analysis_start.elapsed();
        let dispatches = engine.metrics().dispatches();

        let reader = engine.query_reader()?;
        let counts = {
            let project = reader.project()?;
            let functions = project.functions().len();
            let blocks = project.blocks().len();
            let memberships = project
                .functions()
                .iter()
                .map(|function| function.blocks().count())
                .sum::<usize>();
            ProjectCounts {
                blocks,
                functions,
                memberships,
                problems: project.problems().len(),
                switches: project.switches().len(),
                symbols: project.symbols().len(),
            }
        };
        drop(reader);

        let before_close = DiskUsage::measure(&storage_root)?;
        let close_start = Instant::now();
        drop(engine);
        let close_elapsed = close_start.elapsed();
        let after_close = DiskUsage::measure(&storage_root)?;

        println!(
            "mode={},entity_backend={},segment_backend={},load_ns={},project_ns={},\
             analysis_ns={},close_ns={},dispatches={},\
             functions={},blocks={},memberships={},problems={},switches={},symbols={},\
             disk_logical_before={},disk_allocated_before={},\
             disk_logical_after={},disk_allocated_after={}",
            mode.name(),
            mode.entity_backend(),
            mode.segment_backend(),
            load_elapsed.as_nanos(),
            project_elapsed.as_nanos(),
            analysis_elapsed.as_nanos(),
            close_elapsed.as_nanos(),
            dispatches,
            counts.functions,
            counts.blocks,
            counts.memberships,
            counts.problems,
            counts.switches,
            counts.symbols,
            before_close.logical,
            before_close.allocated,
            after_close.logical,
            after_close.allocated,
        );

        Ok(())
    }
}

#[cfg(any(feature = "mdbx", feature = "rocksdb", feature = "sqlite"))]
fn main() -> Result<(), Box<dyn Error>> {
    benchmark::run()
}

#[cfg(not(any(feature = "mdbx", feature = "rocksdb", feature = "sqlite")))]
fn main() {
    eprintln!("the storage timing example requires the `mdbx`, `rocksdb`, or `sqlite` feature");
    process::exit(2);
}
