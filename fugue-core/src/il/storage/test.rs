use super::*;
use crate::il::common::{IlArtefact, IlGraph, IlMetadata};
use crate::il::pcode::PCodeIr;
use crate::storage::{EntityStorage, InMemoryEntityStorage, SegmentStorage};

fn pcode(function: FunctionId, revision: Revision) -> PCodeIr {
    PCodeIr::new(
        IlMetadata::new(function, revision),
        IlGraph::default(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn storage() -> StorageContainer {
    StorageContainer::from_parts(
        EntityStorage::new(InMemoryEntityStorage::new()),
        SegmentStorage::empty(),
    )
    .expect("transient storage should initialise")
}

#[test]
fn repeated_replacement_retains_only_the_final_artefact() {
    let storage = storage();
    let function = FunctionId::new(7);
    let mut staging = IlStaging::default();

    staging
        .replace(&storage, pcode(function, Revision::from(1)))
        .expect("first replacement should stage");
    staging
        .replace(&storage, pcode(function, Revision::from(2)))
        .expect("second replacement should coalesce");

    let writes = staging.prepare().expect("staging should prepare");
    assert_eq!(writes.len(), 1);

    let mut changes = Vec::new();
    staging.for_each_change(|change| changes.push(change));
    assert_eq!(changes.len(), 1);
    assert_eq!(
        changes[0],
        IlStagedChange::Materialised {
            function,
            form: PCodeIr::FORM,
        }
    );
}

#[test]
fn removing_an_unpublished_replacement_elides_the_mutation() {
    let storage = storage();
    let function = FunctionId::new(7);
    let mut staging = IlStaging::default();

    staging
        .replace(&storage, pcode(function, Revision::from(1)))
        .expect("replacement should stage");
    assert!(
        staging
            .remove::<PCodeIr>(&storage, function)
            .expect("replacement should be removable")
            .is_some()
    );

    assert!(
        staging
            .prepare()
            .expect("staging should prepare")
            .is_empty()
    );
    staging.for_each_change(|_| panic!("elided record must not publish a change"));
}

#[test]
fn removing_a_missing_artefact_caches_its_absence() {
    let storage = storage();
    let function = FunctionId::new(7);
    let mut staging = IlStaging::default();

    assert!(
        staging
            .remove::<PCodeIr>(&storage, function)
            .expect("missing artefact lookup should succeed")
            .is_none()
    );
    assert!(
        staging
            .remove::<PCodeIr>(&storage, function)
            .expect("cached missing artefact lookup should succeed")
            .is_none()
    );
}

#[test]
fn an_override_key_round_trips_through_its_encoding() {
    let key = IlOverrideKey::new(FunctionId::new(9), PCodeIr::FORM);
    let mut encoded = Vec::new();
    key.encode(&mut encoded);
    let mut input = encoded.as_slice();

    assert_eq!(IlOverrideKey::decode(&mut input), Some(key));
    assert!(input.is_empty());
}

#[test]
fn a_schema_mismatch_is_reported_rather_than_decoded() {
    let stored = IlOverride {
        form: String::from(PCodeIr::FORM_IDENTIFIER),
        schema: PCodeIr::SCHEMA.value().wrapping_add(1),
        input_revision: 0,
        bytes: Vec::new(),
    };

    assert!(matches!(
        stored.decode::<PCodeIr>(),
        Err(IlStorageError::Il(IlError::SchemaMismatch { .. }))
    ));
}

#[test]
fn an_override_for_an_unregistered_form_reports_its_dialect_as_unavailable() {
    let stored = IlOverride {
        form: String::from("acme.taint.values"),
        schema: PCodeIr::SCHEMA.value(),
        input_revision: 0,
        bytes: Vec::new(),
    };

    assert!(matches!(
        stored.decode::<PCodeIr>(),
        Err(IlStorageError::Il(IlError::DialectUnavailable { .. }))
    ));
}

#[test]
fn deleting_a_function_sweeps_every_stored_form_without_decoding() {
    let storage = storage();
    let function = FunctionId::new(7);
    let mut staging = IlStaging::default();

    staging
        .replace(&storage, pcode(function, Revision::from(1)))
        .expect("replacement should stage");
    let writes = staging.prepare().expect("staging should prepare");
    storage
        .entities()
        .apply_batch(&writes)
        .expect("writes should apply");

    let mut staging = IlStaging::default();
    assert_eq!(
        staging
            .remove_function(&storage, function)
            .expect("the sweep should succeed"),
        1
    );
    assert_eq!(
        staging
            .remove_function(&storage, FunctionId::new(8))
            .expect("an unrelated function has no overrides"),
        0
    );

    let mut swept = Vec::new();
    staging.for_each_change(|change| swept.push(change));
    assert_eq!(
        swept,
        vec![IlStagedChange::Removed {
            function,
            form: PCodeIr::FORM,
        }]
    );
}
