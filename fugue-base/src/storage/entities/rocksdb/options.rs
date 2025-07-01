use serde::{Deserialize, Serialize};
use serde_with::{FromInto, serde_as};

// NOTE: for DBxxx types, we use our own enums to ensure naming conventions, e.g., so we have snake
// case.

#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RocksDbOptions {
    // Basic options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_if_missing: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_missing_column_families: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_if_exists: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub paranoid_checks: Option<bool>,

    // Performance options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub increase_parallelism: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimize_level_style_compaction_memtable_memory_budget: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimize_universal_style_compaction_memtable_memory_budget: Option<usize>,

    // Compression options
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<CompressionType>>")]
    pub compression_type: Option<rocksdb::DBCompressionType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Vec<FromInto<CompressionType>>>")]
    pub compression_per_level: Option<Vec<rocksdb::DBCompressionType>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<CompressionType>>")]
    pub bottommost_compression_type: Option<rocksdb::DBCompressionType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_options: Option<CompressionOptions>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bottommost_compression_options: Option<BottommostCompressionOptions>,

    // Write buffer options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_buffer_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_write_buffer_number: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_write_buffer_number_to_merge: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_write_buffer_size: Option<usize>,

    // Level options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_levels: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub level0_file_num_compaction_trigger: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub level0_slowdown_writes_trigger: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub level0_stop_writes_trigger: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_for_level_base: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_for_level_multiplier: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_compaction_dynamic_level_bytes: Option<bool>,

    // Compaction options
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<CompactionStyle>>")]
    pub compaction_style: Option<rocksdb::DBCompactionStyle>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<CompactionPriority>>")]
    pub compaction_pri: Option<CompactionPriority>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_auto_compactions: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_compaction_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_readahead_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub periodic_compaction_seconds: Option<u64>,

    // File options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_open_files: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_opening_threads: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_file_size_base: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_file_size_multiplier: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_manifest_file_size: Option<usize>,

    // I/O options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_fsync: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_direct_reads: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_direct_io_for_flush_and_compaction: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_mmap_reads: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_mmap_writes: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub advise_random_on_open: Option<bool>,

    // WAL options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_dir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_ttl_seconds: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_size_limit_mb: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<CompressionType>>")]
    pub wal_compression_type: Option<rocksdb::DBCompressionType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_wal_flush: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<RecoveryMode>>")]
    pub wal_recovery_mode: Option<rocksdb::DBRecoveryMode>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_total_wal_size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_bytes_per_sync: Option<u64>,

    // Logging and statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_log_dir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_log_file_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file_time_to_roll: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_log_file_num: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recycle_log_file_num: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_statistics: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_dump_period_sec: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_persist_period_sec: Option<u32>,

    // Memory options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimize_filters_for_hits: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub memtable_prefix_bloom_ratio: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub memtable_whole_key_filtering: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub memtable_huge_page_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arena_block_size: Option<usize>,

    // Background jobs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_background_jobs: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_subcompactions: Option<u32>,

    // Blob storage options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_blob_files: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_blob_size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_file_size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<CompressionType>>")]
    pub blob_compression_type: Option<rocksdb::DBCompressionType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_blob_gc: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gc_age_cutoff: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gc_force_threshold: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_compaction_readahead_size: Option<u64>,

    // Other options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_per_sync: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub writable_file_max_buffer_size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_concurrent_memtable_write: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_write_thread_adaptive_yield: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sequential_skip_in_iterations: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_fd_close_on_exec: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_cache_numshardbits: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_obsolete_files_period_micros: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_checking_sst_file_sizes_on_db_open: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_stats_update_on_db_open: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_write_buffer_size_to_maintain: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_pipelined_write: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unordered_write: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub avoid_unnecessary_blocking_io: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub atomic_flush: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepare_for_bulk_load: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dump_malloc_stats: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_and_verify_wals_in_manifest: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_dbid_to_manifest: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_ingest_behind: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_pending_compaction_bytes_limit: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hard_pending_compaction_bytes_limit: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiterConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub universal_compaction_options: Option<UniversalCompactionOptions>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fifo_compaction_options: Option<FifoCompactionOptions>,

    // Table options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_based_table_options: Option<BlockBasedTableOptions>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub plain_table_options: Option<PlainTableOptions>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cuckoo_table_options: Option<CuckooTableOptions>,

    // Memtable factory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memtable_factory: Option<MemtableFactoryConfig>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionType {
    None,
    Snappy,
    Zlib,
    Bz2,
    Lz4,
    Lz4hc,
    Zstd,
}

impl From<CompressionType> for rocksdb::DBCompressionType {
    fn from(compression: CompressionType) -> Self {
        match compression {
            CompressionType::None => rocksdb::DBCompressionType::None,
            CompressionType::Snappy => rocksdb::DBCompressionType::Snappy,
            CompressionType::Zlib => rocksdb::DBCompressionType::Zlib,
            CompressionType::Bz2 => rocksdb::DBCompressionType::Bz2,
            CompressionType::Lz4 => rocksdb::DBCompressionType::Lz4,
            CompressionType::Lz4hc => rocksdb::DBCompressionType::Lz4hc,
            CompressionType::Zstd => rocksdb::DBCompressionType::Zstd,
        }
    }
}

impl From<rocksdb::DBCompressionType> for CompressionType {
    fn from(compression: rocksdb::DBCompressionType) -> Self {
        match compression {
            rocksdb::DBCompressionType::None => CompressionType::None,
            rocksdb::DBCompressionType::Snappy => CompressionType::Snappy,
            rocksdb::DBCompressionType::Zlib => CompressionType::Zlib,
            rocksdb::DBCompressionType::Bz2 => CompressionType::Bz2,
            rocksdb::DBCompressionType::Lz4 => CompressionType::Lz4,
            rocksdb::DBCompressionType::Lz4hc => CompressionType::Lz4hc,
            rocksdb::DBCompressionType::Zstd => CompressionType::Zstd,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionStyle {
    Level,
    Universal,
    Fifo,
}

impl From<CompactionStyle> for rocksdb::DBCompactionStyle {
    fn from(style: CompactionStyle) -> Self {
        match style {
            CompactionStyle::Level => rocksdb::DBCompactionStyle::Level,
            CompactionStyle::Universal => rocksdb::DBCompactionStyle::Universal,
            CompactionStyle::Fifo => rocksdb::DBCompactionStyle::Fifo,
        }
    }
}

impl From<rocksdb::DBCompactionStyle> for CompactionStyle {
    fn from(style: rocksdb::DBCompactionStyle) -> Self {
        match style {
            rocksdb::DBCompactionStyle::Level => CompactionStyle::Level,
            rocksdb::DBCompactionStyle::Universal => CompactionStyle::Universal,
            rocksdb::DBCompactionStyle::Fifo => CompactionStyle::Fifo,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionPriority {
    ByCompensatedSize,
    OldestLargestSeqFirst,
    OldestSmallestSeqFirst,
    MinOverlappingRatio,
    RoundRobin,
}

impl From<CompactionPriority> for rocksdb::CompactionPri {
    fn from(priority: CompactionPriority) -> Self {
        match priority {
            CompactionPriority::ByCompensatedSize => rocksdb::CompactionPri::ByCompensatedSize,
            CompactionPriority::OldestLargestSeqFirst => {
                rocksdb::CompactionPri::OldestLargestSeqFirst
            }
            CompactionPriority::OldestSmallestSeqFirst => {
                rocksdb::CompactionPri::OldestSmallestSeqFirst
            }
            CompactionPriority::MinOverlappingRatio => rocksdb::CompactionPri::MinOverlappingRatio,
            CompactionPriority::RoundRobin => rocksdb::CompactionPri::RoundRobin,
        }
    }
}

impl From<rocksdb::CompactionPri> for CompactionPriority {
    fn from(priority: rocksdb::CompactionPri) -> Self {
        match priority {
            rocksdb::CompactionPri::ByCompensatedSize => CompactionPriority::ByCompensatedSize,
            rocksdb::CompactionPri::OldestLargestSeqFirst => {
                CompactionPriority::OldestLargestSeqFirst
            }
            rocksdb::CompactionPri::OldestSmallestSeqFirst => {
                CompactionPriority::OldestSmallestSeqFirst
            }
            rocksdb::CompactionPri::MinOverlappingRatio => CompactionPriority::MinOverlappingRatio,
            rocksdb::CompactionPri::RoundRobin => CompactionPriority::RoundRobin,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMode {
    TolerateCorruptedTailRecords,
    AbsoluteConsistency,
    PointInTime,
    SkipAnyCorruptedRecord,
}

impl From<RecoveryMode> for rocksdb::DBRecoveryMode {
    fn from(mode: RecoveryMode) -> Self {
        match mode {
            RecoveryMode::TolerateCorruptedTailRecords => {
                rocksdb::DBRecoveryMode::TolerateCorruptedTailRecords
            }
            RecoveryMode::AbsoluteConsistency => rocksdb::DBRecoveryMode::AbsoluteConsistency,
            RecoveryMode::PointInTime => rocksdb::DBRecoveryMode::PointInTime,
            RecoveryMode::SkipAnyCorruptedRecord => rocksdb::DBRecoveryMode::SkipAnyCorruptedRecord,
        }
    }
}

impl From<rocksdb::DBRecoveryMode> for RecoveryMode {
    fn from(mode: rocksdb::DBRecoveryMode) -> Self {
        match mode {
            rocksdb::DBRecoveryMode::TolerateCorruptedTailRecords => {
                RecoveryMode::TolerateCorruptedTailRecords
            }
            rocksdb::DBRecoveryMode::AbsoluteConsistency => RecoveryMode::AbsoluteConsistency,
            rocksdb::DBRecoveryMode::PointInTime => RecoveryMode::PointInTime,
            rocksdb::DBRecoveryMode::SkipAnyCorruptedRecord => RecoveryMode::SkipAnyCorruptedRecord,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Header,
}

impl From<LogLevel> for rocksdb::LogLevel {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Debug => rocksdb::LogLevel::Debug,
            LogLevel::Info => rocksdb::LogLevel::Info,
            LogLevel::Warn => rocksdb::LogLevel::Warn,
            LogLevel::Error => rocksdb::LogLevel::Error,
            LogLevel::Fatal => rocksdb::LogLevel::Fatal,
            LogLevel::Header => rocksdb::LogLevel::Header,
        }
    }
}

impl From<rocksdb::LogLevel> for LogLevel {
    fn from(level: rocksdb::LogLevel) -> Self {
        match level {
            rocksdb::LogLevel::Debug => LogLevel::Debug,
            rocksdb::LogLevel::Info => LogLevel::Info,
            rocksdb::LogLevel::Warn => LogLevel::Warn,
            rocksdb::LogLevel::Error => LogLevel::Error,
            rocksdb::LogLevel::Fatal => LogLevel::Fatal,
            rocksdb::LogLevel::Header => LogLevel::Header,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionOptions {
    pub w_bits: i32,
    pub level: i32,
    pub strategy: i32,
    pub max_dict_bytes: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BottommostCompressionOptions {
    pub w_bits: i32,
    pub level: i32,
    pub strategy: i32,
    pub max_dict_bytes: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    pub rate_bytes_per_sec: i64,
    pub refill_period_us: i64,
    pub fairness: i32,
    pub auto_tuned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SstFileManagerConfig {
    pub max_allowed_space_usage: u64,
    pub compaction_buffer_size: u64,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UniversalCompactionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_ratio: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_merge_width: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_merge_width: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size_amplification_percent: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_size_percent: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<FromInto<UniversalCompactionStopStyle>>")]
    pub stop_style: Option<UniversalCompactionStopStyle>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UniversalCompactionStopStyle {
    Similar,
    Total,
}

impl From<UniversalCompactionStopStyle> for rocksdb::UniversalCompactionStopStyle {
    fn from(style: UniversalCompactionStopStyle) -> Self {
        match style {
            UniversalCompactionStopStyle::Similar => rocksdb::UniversalCompactionStopStyle::Similar,
            UniversalCompactionStopStyle::Total => rocksdb::UniversalCompactionStopStyle::Total,
        }
    }
}

impl From<rocksdb::UniversalCompactionStopStyle> for UniversalCompactionStopStyle {
    fn from(style: rocksdb::UniversalCompactionStopStyle) -> Self {
        match style {
            rocksdb::UniversalCompactionStopStyle::Similar => UniversalCompactionStopStyle::Similar,
            rocksdb::UniversalCompactionStopStyle::Total => UniversalCompactionStopStyle::Total,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FifoCompactionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_table_files_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockBasedTableOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_block_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_filters: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_index_and_filter_blocks: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_l0_filter_and_index_blocks_in_cache: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_top_level_index_and_filter: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_type: Option<BlockBasedIndexType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_block_index_type: Option<DataBlockIndexType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_block_hash_ratio: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_type: Option<ChecksumType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_block_cache: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_cache_type: Option<BlockCacheType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_cache_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bloom_filter_policy: Option<BloomFilterPolicy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_version: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_restart_interval: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_block_restart_interval: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub whole_key_filtering: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimize_filters_for_memory: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockBasedIndexType {
    BinarySearch,
    HashSearch,
    TwoLevelIndexSearch,
}

impl From<BlockBasedIndexType> for rocksdb::BlockBasedIndexType {
    fn from(index_type: BlockBasedIndexType) -> Self {
        match index_type {
            BlockBasedIndexType::BinarySearch => rocksdb::BlockBasedIndexType::BinarySearch,
            BlockBasedIndexType::HashSearch => rocksdb::BlockBasedIndexType::HashSearch,
            BlockBasedIndexType::TwoLevelIndexSearch => {
                rocksdb::BlockBasedIndexType::TwoLevelIndexSearch
            }
        }
    }
}

impl From<rocksdb::BlockBasedIndexType> for BlockBasedIndexType {
    fn from(index_type: rocksdb::BlockBasedIndexType) -> Self {
        match index_type {
            rocksdb::BlockBasedIndexType::BinarySearch => BlockBasedIndexType::BinarySearch,
            rocksdb::BlockBasedIndexType::HashSearch => BlockBasedIndexType::HashSearch,
            rocksdb::BlockBasedIndexType::TwoLevelIndexSearch => {
                BlockBasedIndexType::TwoLevelIndexSearch
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BlockCacheType {
    #[serde(rename = "lru")]
    Lru { capacity: usize },
    #[serde(rename = "hyper_clock")]
    HyperClock {
        capacity: usize,
        estimated_entry_charge: usize,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataBlockIndexType {
    BinarySearch,
    BinaryAndHash,
}

impl From<DataBlockIndexType> for rocksdb::DataBlockIndexType {
    fn from(index_type: DataBlockIndexType) -> Self {
        match index_type {
            DataBlockIndexType::BinarySearch => rocksdb::DataBlockIndexType::BinarySearch,
            DataBlockIndexType::BinaryAndHash => rocksdb::DataBlockIndexType::BinaryAndHash,
        }
    }
}

impl From<rocksdb::DataBlockIndexType> for DataBlockIndexType {
    fn from(index_type: rocksdb::DataBlockIndexType) -> Self {
        match index_type {
            rocksdb::DataBlockIndexType::BinarySearch => DataBlockIndexType::BinarySearch,
            rocksdb::DataBlockIndexType::BinaryAndHash => DataBlockIndexType::BinaryAndHash,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumType {
    NoChecksum,
    Crc32c,
    XxHash,
    XxHash64,
    Xxh3,
}

impl From<ChecksumType> for rocksdb::ChecksumType {
    fn from(checksum: ChecksumType) -> Self {
        match checksum {
            ChecksumType::NoChecksum => rocksdb::ChecksumType::NoChecksum,
            ChecksumType::Crc32c => rocksdb::ChecksumType::CRC32c,
            ChecksumType::XxHash => rocksdb::ChecksumType::XXHash,
            ChecksumType::XxHash64 => rocksdb::ChecksumType::XXHash64,
            ChecksumType::Xxh3 => rocksdb::ChecksumType::XXH3,
        }
    }
}

impl From<rocksdb::ChecksumType> for ChecksumType {
    fn from(checksum: rocksdb::ChecksumType) -> Self {
        match checksum {
            rocksdb::ChecksumType::NoChecksum => ChecksumType::NoChecksum,
            rocksdb::ChecksumType::CRC32c => ChecksumType::Crc32c,
            rocksdb::ChecksumType::XXHash => ChecksumType::XxHash,
            rocksdb::ChecksumType::XXHash64 => ChecksumType::XxHash64,
            rocksdb::ChecksumType::XXH3 => ChecksumType::Xxh3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BloomFilterPolicy {
    #[serde(rename = "bloom")]
    Bloom {
        bits_per_key: f64,
        block_based: bool,
    },
    #[serde(rename = "ribbon")]
    Ribbon { bloom_equivalent_bits_per_key: f64 },
    #[serde(rename = "hybrid_ribbon")]
    HybridRibbon {
        bloom_equivalent_bits_per_key: f64,
        bloom_before_level: i32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlainTableOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key_length: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bloom_bits_per_key: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_table_ratio: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_sparseness: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub huge_page_tlb_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_type: Option<PlainTableEncodingType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_scan_mode: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_index_in_file: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlainTableEncodingType {
    Plain,
    Prefix,
}

impl From<PlainTableEncodingType> for rocksdb::KeyEncodingType {
    fn from(encoding: PlainTableEncodingType) -> Self {
        match encoding {
            PlainTableEncodingType::Plain => rocksdb::KeyEncodingType::Plain,
            PlainTableEncodingType::Prefix => rocksdb::KeyEncodingType::Prefix,
        }
    }
}

impl From<rocksdb::KeyEncodingType> for PlainTableEncodingType {
    fn from(encoding: rocksdb::KeyEncodingType) -> Self {
        match encoding {
            rocksdb::KeyEncodingType::Plain => PlainTableEncodingType::Plain,
            rocksdb::KeyEncodingType::Prefix => PlainTableEncodingType::Prefix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CuckooTableOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_ratio: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_search_depth: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cuckoo_block_size: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_as_first_hash: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_module_hash: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MemtableFactoryConfig {
    #[serde(rename = "vector")]
    Vector,

    #[serde(rename = "hash_skip_list")]
    HashSkipList {
        bucket_count: usize,
        height: i32,
        branching_factor: i32,
    },

    #[serde(rename = "hash_link_list")]
    HashLinkList { bucket_count: usize },
}

impl RocksDbOptions {
    /// Create a new empty options structure
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply these options to a rocksdb Options instance
    pub fn apply(&self, opts: &mut rocksdb::Options) {
        // Basic options
        if let Some(v) = self.create_if_missing {
            opts.create_if_missing(v);
        }
        if let Some(v) = self.create_missing_column_families {
            opts.create_missing_column_families(v);
        }
        if let Some(v) = self.error_if_exists {
            opts.set_error_if_exists(v);
        }
        if let Some(v) = self.paranoid_checks {
            opts.set_paranoid_checks(v);
        }

        // Performance options
        if let Some(v) = self.increase_parallelism {
            opts.increase_parallelism(v);
        }
        if let Some(v) = self.optimize_level_style_compaction_memtable_memory_budget {
            opts.optimize_level_style_compaction(v);
        }
        if let Some(v) = self.optimize_universal_style_compaction_memtable_memory_budget {
            opts.optimize_universal_style_compaction(v);
        }

        // Compression options
        if let Some(v) = self.compression_type {
            opts.set_compression_type(v);
        }
        if let Some(ref v) = self.compression_per_level {
            opts.set_compression_per_level(v);
        }
        if let Some(v) = self.bottommost_compression_type {
            opts.set_bottommost_compression_type(v);
        }
        if let Some(ref v) = self.compression_options {
            opts.set_compression_options(v.w_bits, v.level, v.strategy, v.max_dict_bytes);
        }
        if let Some(ref v) = self.bottommost_compression_options {
            opts.set_bottommost_compression_options(
                v.w_bits,
                v.level,
                v.strategy,
                v.max_dict_bytes,
                v.enabled,
            );
        }

        // Write buffer options
        if let Some(v) = self.write_buffer_size {
            opts.set_write_buffer_size(v);
        }
        if let Some(v) = self.max_write_buffer_number {
            opts.set_max_write_buffer_number(v);
        }
        if let Some(v) = self.min_write_buffer_number_to_merge {
            opts.set_min_write_buffer_number_to_merge(v);
        }
        if let Some(v) = self.db_write_buffer_size {
            opts.set_db_write_buffer_size(v);
        }

        // Level options
        if let Some(v) = self.num_levels {
            opts.set_num_levels(v);
        }
        if let Some(v) = self.level0_file_num_compaction_trigger {
            opts.set_level_zero_file_num_compaction_trigger(v);
        }
        if let Some(v) = self.level0_slowdown_writes_trigger {
            opts.set_level_zero_slowdown_writes_trigger(v);
        }
        if let Some(v) = self.level0_stop_writes_trigger {
            opts.set_level_zero_stop_writes_trigger(v);
        }
        if let Some(v) = self.max_bytes_for_level_base {
            opts.set_max_bytes_for_level_base(v);
        }
        if let Some(v) = self.max_bytes_for_level_multiplier {
            opts.set_max_bytes_for_level_multiplier(v);
        }
        if let Some(v) = self.level_compaction_dynamic_level_bytes {
            opts.set_level_compaction_dynamic_level_bytes(v);
        }

        // Compaction options
        if let Some(v) = self.compaction_style {
            opts.set_compaction_style(v);
        }
        if let Some(v) = self.compaction_pri {
            opts.set_compaction_pri(v.into());
        }
        if let Some(v) = self.disable_auto_compactions {
            opts.set_disable_auto_compactions(v);
        }
        if let Some(v) = self.max_compaction_bytes {
            opts.set_max_compaction_bytes(v);
        }
        if let Some(v) = self.compaction_readahead_size {
            opts.set_compaction_readahead_size(v);
        }
        if let Some(v) = self.periodic_compaction_seconds {
            opts.set_periodic_compaction_seconds(v);
        }

        // File options
        if let Some(v) = self.max_open_files {
            opts.set_max_open_files(v);
        }
        if let Some(v) = self.max_file_opening_threads {
            opts.set_max_file_opening_threads(v);
        }
        if let Some(v) = self.target_file_size_base {
            opts.set_target_file_size_base(v);
        }
        if let Some(v) = self.target_file_size_multiplier {
            opts.set_target_file_size_multiplier(v);
        }
        if let Some(v) = self.max_manifest_file_size {
            opts.set_max_manifest_file_size(v);
        }

        // I/O options
        if let Some(v) = self.use_fsync {
            opts.set_use_fsync(v);
        }
        if let Some(v) = self.use_direct_reads {
            opts.set_use_direct_reads(v);
        }
        if let Some(v) = self.use_direct_io_for_flush_and_compaction {
            opts.set_use_direct_io_for_flush_and_compaction(v);
        }
        if let Some(v) = self.allow_mmap_reads {
            opts.set_allow_mmap_reads(v);
        }
        if let Some(v) = self.allow_mmap_writes {
            opts.set_allow_mmap_writes(v);
        }
        if let Some(v) = self.advise_random_on_open {
            opts.set_advise_random_on_open(v);
        }

        // WAL options
        if let Some(ref v) = self.wal_dir {
            opts.set_wal_dir(v);
        }
        if let Some(v) = self.wal_ttl_seconds {
            opts.set_wal_ttl_seconds(v);
        }
        if let Some(v) = self.wal_size_limit_mb {
            opts.set_wal_size_limit_mb(v);
        }
        if let Some(v) = self.wal_compression_type {
            opts.set_wal_compression_type(v);
        }
        if let Some(v) = self.manual_wal_flush {
            opts.set_manual_wal_flush(v);
        }
        if let Some(v) = self.wal_recovery_mode {
            opts.set_wal_recovery_mode(v);
        }
        if let Some(v) = self.max_total_wal_size {
            opts.set_max_total_wal_size(v);
        }
        if let Some(v) = self.wal_bytes_per_sync {
            opts.set_wal_bytes_per_sync(v);
        }

        // Logging and statistics
        if let Some(ref v) = self.db_log_dir {
            opts.set_db_log_dir(v);
        }
        if let Some(v) = self.log_level {
            opts.set_log_level(v.into());
        }
        if let Some(v) = self.max_log_file_size {
            opts.set_max_log_file_size(v);
        }
        if let Some(v) = self.log_file_time_to_roll {
            opts.set_log_file_time_to_roll(v);
        }
        if let Some(v) = self.keep_log_file_num {
            opts.set_keep_log_file_num(v);
        }
        if let Some(v) = self.recycle_log_file_num {
            opts.set_recycle_log_file_num(v);
        }
        if let Some(true) = self.enable_statistics {
            opts.enable_statistics();
        }
        if let Some(v) = self.stats_dump_period_sec {
            opts.set_stats_dump_period_sec(v);
        }
        if let Some(v) = self.stats_persist_period_sec {
            opts.set_stats_persist_period_sec(v);
        }

        // Memory options
        if let Some(v) = self.optimize_filters_for_hits {
            opts.set_optimize_filters_for_hits(v);
        }
        if let Some(v) = self.memtable_prefix_bloom_ratio {
            opts.set_memtable_prefix_bloom_ratio(v);
        }
        if let Some(v) = self.memtable_whole_key_filtering {
            opts.set_memtable_whole_key_filtering(v);
        }
        if let Some(v) = self.memtable_huge_page_size {
            opts.set_memtable_huge_page_size(v);
        }
        if let Some(v) = self.arena_block_size {
            opts.set_arena_block_size(v);
        }

        // Background jobs
        if let Some(v) = self.max_background_jobs {
            opts.set_max_background_jobs(v);
        }
        if let Some(v) = self.max_subcompactions {
            opts.set_max_subcompactions(v);
        }

        // Blob storage options
        if let Some(v) = self.enable_blob_files {
            opts.set_enable_blob_files(v);
        }
        if let Some(v) = self.min_blob_size {
            opts.set_min_blob_size(v);
        }
        if let Some(v) = self.blob_file_size {
            opts.set_blob_file_size(v);
        }
        if let Some(v) = self.blob_compression_type {
            opts.set_blob_compression_type(v);
        }
        if let Some(v) = self.enable_blob_gc {
            opts.set_enable_blob_gc(v);
        }
        if let Some(v) = self.blob_gc_age_cutoff {
            opts.set_blob_gc_age_cutoff(v);
        }
        if let Some(v) = self.blob_gc_force_threshold {
            opts.set_blob_gc_force_threshold(v);
        }
        if let Some(v) = self.blob_compaction_readahead_size {
            opts.set_blob_compaction_readahead_size(v);
        }

        // Other options
        if let Some(v) = self.bytes_per_sync {
            opts.set_bytes_per_sync(v);
        }
        if let Some(v) = self.writable_file_max_buffer_size {
            opts.set_writable_file_max_buffer_size(v);
        }
        if let Some(v) = self.allow_concurrent_memtable_write {
            opts.set_allow_concurrent_memtable_write(v);
        }
        if let Some(v) = self.enable_write_thread_adaptive_yield {
            opts.set_enable_write_thread_adaptive_yield(v);
        }
        if let Some(v) = self.max_sequential_skip_in_iterations {
            opts.set_max_sequential_skip_in_iterations(v);
        }
        if let Some(v) = self.is_fd_close_on_exec {
            opts.set_is_fd_close_on_exec(v);
        }
        if let Some(v) = self.table_cache_numshardbits {
            opts.set_table_cache_num_shard_bits(v);
        }
        if let Some(v) = self.delete_obsolete_files_period_micros {
            opts.set_delete_obsolete_files_period_micros(v);
        }
        if let Some(v) = self.skip_checking_sst_file_sizes_on_db_open {
            opts.set_skip_checking_sst_file_sizes_on_db_open(v);
        }
        if let Some(v) = self.skip_stats_update_on_db_open {
            opts.set_skip_stats_update_on_db_open(v);
        }
        if let Some(v) = self.max_write_buffer_size_to_maintain {
            opts.set_max_write_buffer_size_to_maintain(v);
        }
        if let Some(v) = self.enable_pipelined_write {
            opts.set_enable_pipelined_write(v);
        }
        if let Some(v) = self.unordered_write {
            opts.set_unordered_write(v);
        }
        if let Some(v) = self.avoid_unnecessary_blocking_io {
            opts.set_avoid_unnecessary_blocking_io(v);
        }
        if let Some(v) = self.atomic_flush {
            opts.set_atomic_flush(v);
        }
        if let Some(true) = self.prepare_for_bulk_load {
            opts.prepare_for_bulk_load();
        }
        if let Some(v) = self.dump_malloc_stats {
            opts.set_dump_malloc_stats(v);
        }

        if let Some(v) = self.track_and_verify_wals_in_manifest {
            opts.set_track_and_verify_wals_in_manifest(v);
        }
        if let Some(v) = self.write_dbid_to_manifest {
            opts.set_write_dbid_to_manifest(v);
        }
        if let Some(v) = self.allow_ingest_behind {
            opts.set_allow_ingest_behind(v);
        }
        if let Some(v) = self.soft_pending_compaction_bytes_limit {
            opts.set_soft_pending_compaction_bytes_limit(v);
        }
        if let Some(v) = self.hard_pending_compaction_bytes_limit {
            opts.set_hard_pending_compaction_bytes_limit(v);
        }
        if let Some(ref v) = self.rate_limiter {
            if v.auto_tuned {
                opts.set_auto_tuned_ratelimiter(
                    v.rate_bytes_per_sec,
                    v.refill_period_us,
                    v.fairness,
                );
            } else {
                opts.set_ratelimiter(v.rate_bytes_per_sec, v.refill_period_us, v.fairness);
            }
        }
        if let Some(ref v) = self.universal_compaction_options {
            let mut compact_opts = rocksdb::UniversalCompactOptions::default();
            if let Some(size_ratio) = v.size_ratio {
                compact_opts.set_size_ratio(size_ratio);
            }
            if let Some(min_merge_width) = v.min_merge_width {
                compact_opts.set_min_merge_width(min_merge_width);
            }
            if let Some(max_merge_width) = v.max_merge_width {
                compact_opts.set_max_merge_width(max_merge_width);
            }
            if let Some(max_size_amplification_percent) = v.max_size_amplification_percent {
                compact_opts.set_max_size_amplification_percent(max_size_amplification_percent);
            }
            if let Some(compression_size_percent) = v.compression_size_percent {
                compact_opts.set_compression_size_percent(compression_size_percent);
            }
            if let Some(stop_style) = v.stop_style {
                compact_opts.set_stop_style(stop_style.into());
            }
            opts.set_universal_compaction_options(&compact_opts);
        }
        if let Some(ref v) = self.fifo_compaction_options {
            let mut fifo_opts = rocksdb::FifoCompactOptions::default();
            if let Some(max_table_files_size) = v.max_table_files_size {
                fifo_opts.set_max_table_files_size(max_table_files_size);
            }
            opts.set_fifo_compaction_options(&fifo_opts);
        }

        // Table options
        if let Some(ref v) = self.block_based_table_options {
            let mut table_opts = rocksdb::BlockBasedOptions::default();
            if let Some(block_size) = v.block_size {
                table_opts.set_block_size(block_size);
            }
            if let Some(metadata_block_size) = v.metadata_block_size {
                table_opts.set_metadata_block_size(metadata_block_size);
            }
            if let Some(partition_filters) = v.partition_filters {
                table_opts.set_partition_filters(partition_filters);
            }
            if let Some(cache_index_and_filter_blocks) = v.cache_index_and_filter_blocks {
                table_opts.set_cache_index_and_filter_blocks(cache_index_and_filter_blocks);
            }
            if let Some(pin_l0_filter_and_index_blocks_in_cache) =
                v.pin_l0_filter_and_index_blocks_in_cache
            {
                table_opts.set_pin_l0_filter_and_index_blocks_in_cache(
                    pin_l0_filter_and_index_blocks_in_cache,
                );
            }
            if let Some(pin_top_level_index_and_filter) = v.pin_top_level_index_and_filter {
                table_opts.set_pin_top_level_index_and_filter(pin_top_level_index_and_filter);
            }
            if let Some(index_type) = v.index_type {
                table_opts.set_index_type(index_type.into());
            }
            if let Some(data_block_index_type) = v.data_block_index_type {
                table_opts.set_data_block_index_type(data_block_index_type.into());
            }
            if let Some(data_block_hash_ratio) = v.data_block_hash_ratio {
                table_opts.set_data_block_hash_ratio(data_block_hash_ratio);
            }
            if let Some(checksum_type) = v.checksum_type {
                table_opts.set_checksum_type(checksum_type.into());
            }
            if let Some(true) = v.no_block_cache {
                table_opts.disable_cache();
            } else if let Some(ref block_cache_type) = v.block_cache_type {
                let block_cache = match block_cache_type {
                    BlockCacheType::Lru { capacity } => rocksdb::Cache::new_lru_cache(*capacity),
                    BlockCacheType::HyperClock {
                        capacity,
                        estimated_entry_charge,
                    } => rocksdb::Cache::new_hyper_clock_cache(*capacity, *estimated_entry_charge),
                };
                table_opts.set_block_cache(&block_cache);
            }
            if let Some(ref bloom_filter_policy) = v.bloom_filter_policy {
                match bloom_filter_policy {
                    BloomFilterPolicy::Bloom {
                        bits_per_key,
                        block_based,
                    } => table_opts.set_bloom_filter(*bits_per_key, *block_based),
                    BloomFilterPolicy::Ribbon {
                        bloom_equivalent_bits_per_key,
                    } => table_opts.set_ribbon_filter(*bloom_equivalent_bits_per_key),
                    BloomFilterPolicy::HybridRibbon {
                        bloom_equivalent_bits_per_key,
                        bloom_before_level,
                    } => table_opts.set_hybrid_ribbon_filter(
                        *bloom_equivalent_bits_per_key,
                        *bloom_before_level,
                    ),
                }
            }
            if let Some(format_version) = v.format_version {
                table_opts.set_format_version(format_version);
            }
            if let Some(block_restart_interval) = v.block_restart_interval {
                table_opts.set_block_restart_interval(block_restart_interval);
            }
            if let Some(index_block_restart_interval) = v.index_block_restart_interval {
                table_opts.set_index_block_restart_interval(index_block_restart_interval);
            }
            if let Some(whole_key_filtering) = v.whole_key_filtering {
                table_opts.set_whole_key_filtering(whole_key_filtering);
            }
            if let Some(optimize_filters_for_memory) = v.optimize_filters_for_memory {
                table_opts.set_optimize_filters_for_memory(optimize_filters_for_memory);
            }
            opts.set_block_based_table_factory(&table_opts);
        }

        if let Some(ref v) = self.plain_table_options {
            let mut table_opts = rocksdb::PlainTableFactoryOptions {
                user_key_length: 0,
                bloom_bits_per_key: 10,
                hash_table_ratio: 0.75,
                index_sparseness: 16,
                huge_page_tlb_size: 0,
                encoding_type: PlainTableEncodingType::Plain.into(),
                full_scan_mode: false,
                store_index_in_file: false,
            };

            if let Some(user_key_length) = v.user_key_length {
                table_opts.user_key_length = user_key_length;
            }
            if let Some(bloom_bits_per_key) = v.bloom_bits_per_key {
                table_opts.bloom_bits_per_key = bloom_bits_per_key;
            }
            if let Some(hash_table_ratio) = v.hash_table_ratio {
                table_opts.hash_table_ratio = hash_table_ratio;
            }
            if let Some(index_sparseness) = v.index_sparseness {
                table_opts.index_sparseness = index_sparseness;
            }
            if let Some(huge_page_tlb_size) = v.huge_page_tlb_size {
                table_opts.huge_page_tlb_size = huge_page_tlb_size;
            }
            if let Some(encoding_type) = v.encoding_type {
                table_opts.encoding_type = encoding_type.into();
            }
            if let Some(full_scan_mode) = v.full_scan_mode {
                table_opts.full_scan_mode = full_scan_mode;
            }
            if let Some(store_index_in_file) = v.store_index_in_file {
                table_opts.store_index_in_file = store_index_in_file;
            }
            opts.set_plain_table_factory(&table_opts);
        }

        if let Some(ref v) = self.cuckoo_table_options {
            let mut table_opts = rocksdb::CuckooTableOptions::default();
            if let Some(hash_ratio) = v.hash_ratio {
                table_opts.set_hash_ratio(hash_ratio);
            }
            if let Some(max_search_depth) = v.max_search_depth {
                table_opts.set_max_search_depth(max_search_depth);
            }
            if let Some(cuckoo_block_size) = v.cuckoo_block_size {
                table_opts.set_cuckoo_block_size(cuckoo_block_size);
            }
            if let Some(identity_as_first_hash) = v.identity_as_first_hash {
                table_opts.set_identity_as_first_hash(identity_as_first_hash);
            }
            if let Some(use_module_hash) = v.use_module_hash {
                table_opts.set_use_module_hash(use_module_hash);
            }
            opts.set_cuckoo_table_factory(&table_opts);
        }

        if let Some(ref v) = self.memtable_factory {
            match v {
                MemtableFactoryConfig::Vector => {
                    opts.set_memtable_factory(rocksdb::MemtableFactory::Vector)
                }
                MemtableFactoryConfig::HashSkipList {
                    bucket_count,
                    height,
                    branching_factor,
                } => {
                    opts.set_memtable_factory(rocksdb::MemtableFactory::HashSkipList {
                        bucket_count: *bucket_count,
                        height: *height,
                        branching_factor: *branching_factor,
                    });
                }
                MemtableFactoryConfig::HashLinkList { bucket_count } => {
                    opts.set_memtable_factory(rocksdb::MemtableFactory::HashLinkList {
                        bucket_count: *bucket_count,
                    });
                }
            }
        }
    }
}
