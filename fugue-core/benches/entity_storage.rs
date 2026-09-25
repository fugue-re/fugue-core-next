use std::error::Error;
use std::hint::black_box;
use std::ops::Bound;
use std::time::{Duration, Instant};

use fugue_core::storage::{
    BufferedEntityWriter, ENTITY_PROJECT_REVISION_ID, EntityKeyPrefix, EntityStorageError,
    EntityStorageProvider, EntityStorageWriteTransaction, InMemoryEntityStorage, ProjectEntity,
};
use fugue_core::types::BytesOrSlice;

const ROW_COUNTS: [usize; 3] = [1_024, 16_384, 65_536];
const SAMPLE_TIME: Duration = Duration::from_millis(500);
const VALUE: [u8; 32] = [0x5a; 32];

fn populate(rows: usize) -> Result<(InMemoryEntityStorage, EntityKeyPrefix), EntityStorageError> {
    let storage = InMemoryEntityStorage::new();
    let seed = ENTITY_PROJECT_REVISION_ID.key_for(&ProjectEntity::Revision);
    let (prefix, _) =
        EntityKeyPrefix::split(seed.as_ref()).expect("a key produced by an entity ID has a prefix");

    for index in 0..rows {
        let key = prefix.join(&(index as u64).to_be_bytes());
        storage.insert(key.as_ref(), BytesOrSlice::from(VALUE.as_slice()))?;
    }

    Ok((storage, prefix))
}

fn measure<F>(name: &str, rows: usize, mut scan: F) -> Result<(), EntityStorageError>
where
    F: FnMut() -> Result<(usize, usize), EntityStorageError>,
{
    let (items, checksum) = scan()?;
    black_box(checksum);

    let start = Instant::now();
    let mut scans = 0usize;
    let mut total_items = 0usize;
    while start.elapsed() < SAMPLE_TIME {
        let (items, checksum) = scan()?;
        black_box(checksum);
        scans += 1;
        total_items += items;
    }

    let elapsed = start.elapsed();
    let nanos_per_row = elapsed.as_nanos() as f64 / total_items as f64;
    println!(
        "bench={name},rows={rows},items_per_scan={items},scans={scans},elapsed_ns={},ns_per_row={nanos_per_row:.2}",
        elapsed.as_nanos(),
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    for rows in ROW_COUNTS {
        let (storage, prefix) = populate(rows)?;
        let keys = (0..rows)
            .map(|index| prefix.join(&(index as u64).to_be_bytes()))
            .collect::<Vec<_>>();

        measure("get", rows, || {
            let mut checksum = 0usize;
            for key in &keys {
                checksum ^= storage
                    .get(key.as_ref())?
                    .expect("the benchmark key exists")
                    .len();
            }
            Ok((keys.len(), checksum))
        })?;

        measure("insert_replace", rows, || {
            for key in &keys {
                storage.insert(key.as_ref(), BytesOrSlice::from(VALUE.as_slice()))?;
            }
            Ok((keys.len(), keys.len()))
        })?;

        measure("remove_insert", rows, || {
            for key in &keys {
                storage.remove(key.as_ref())?;
                storage.insert(key.as_ref(), BytesOrSlice::from(VALUE.as_slice()))?;
            }
            Ok((keys.len(), keys.len()))
        })?;

        measure("write_transaction", rows, || {
            let mut writer = storage.write_transaction()?;
            for key in &keys {
                writer.insert(key.as_ref(), BytesOrSlice::from(VALUE.as_slice()))?;
            }
            writer.commit()?;
            Ok((keys.len(), keys.len()))
        })?;

        measure("buffered_write_transaction", rows, || {
            let mut writer = BufferedEntityWriter::new(&storage);
            for key in &keys {
                writer.insert(key.as_ref(), BytesOrSlice::from(VALUE.as_slice()))?;
            }
            Box::new(writer).commit()?;
            Ok((keys.len(), keys.len()))
        })?;

        measure("iter_prefix_keys", rows, || {
            let mut checksum = 0usize;
            let mut items = 0usize;
            for key in storage.iter_prefix_keys(prefix.as_ref())? {
                checksum ^= key?.len();
                items += 1;
            }
            Ok((items, checksum))
        })?;

        measure("iter_prefix", rows, || {
            let mut checksum = 0usize;
            let mut items = 0usize;
            for entry in storage.iter_prefix(prefix.as_ref())? {
                let (key, value) = entry?;
                checksum ^= key.len() + value.len();
                items += 1;
            }
            Ok((items, checksum))
        })?;

        let start = prefix.join(&((rows / 2) as u64).to_be_bytes());
        measure("iter_range", rows, || {
            let mut checksum = 0usize;
            let mut items = 0usize;
            for entry in storage.iter_range(prefix.as_ref(), Bound::Included(start.as_ref()))? {
                let (key, value) = entry?;
                checksum ^= key.len() + value.len();
                items += 1;
            }
            Ok((items, checksum))
        })?;

        measure("iter_range_page", rows, || {
            let mut checksum = 0usize;
            let mut items = 0usize;
            let iter = storage.iter_range(prefix.as_ref(), Bound::Included(start.as_ref()))?;
            for entry in iter.take(256) {
                let (key, value) = entry?;
                checksum ^= key.len() + value.len();
                items += 1;
            }
            Ok((items, checksum))
        })?;

        measure("iter_prefix_as", rows, || {
            let mut checksum = 0usize;
            let mut items = 0usize;
            let iter = storage
                .iter_prefix_as(prefix.as_ref(), |key, value| Ok(key.len() + value.len()))?;
            for size in iter {
                checksum ^= size?;
                items += 1;
            }
            Ok((items, checksum))
        })?;
    }

    Ok(())
}
