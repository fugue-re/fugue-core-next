use fugue_core::ir::{
    Address, AddressTable, AddressWithContext, Switch, SwitchCase, SwitchCaseLabel, SwitchModel,
    SwitchProperties, SwitchTable,
};
use fugue_core::lifter::ContextSet;
use fugue_core::storage::EntityStorage;
use fugue_core::storage::entities::InMemoryEntityStorage;

fn table_of(size: u32, shift: u8) -> AddressTable {
    AddressTable::new(Address::from(0x2000u64), size)
        .with_element_count(4)
        .with_shift(shift)
}

#[test]
fn table_insert_get_modify_remove() {
    let mut table = SwitchTable::new_transient();
    let branch = Address::from(0x401000u64);

    let id = table
        .insert(branch, |id, branch| {
            Ok(Switch::new(
                id,
                branch,
                SwitchModel::Absolute(table_of(4, 0)),
            ))
        })
        .unwrap();
    assert_eq!(table.len(), 1);
    assert!(table.contains(branch));
    assert_eq!(table.get_by_branch(branch).unwrap().id(), id);

    table
        .modify_by_id(id, |switch| {
            switch.add_case(SwitchCase::new(AddressWithContext::new(
                Address::from(0x401100u64),
                ContextSet::default(),
            )));
        })
        .unwrap();
    assert_eq!(table.get_by_id(id).unwrap().case_count(), 1);

    assert!(table.remove_by_id(id));
    assert!(table.is_empty());
}

#[test]
fn removed_id_slot_reuse_invalidates_old_id() {
    let mut table = SwitchTable::new_transient();
    let first = table
        .insert(Address::from(0x1000u64), |id, branch| {
            Ok(Switch::new(id, branch, SwitchModel::Explicit))
        })
        .unwrap();
    assert!(table.remove_by_id(first));

    let second = table
        .insert(Address::from(0x2000u64), |id, branch| {
            Ok(Switch::new(id, branch, SwitchModel::Explicit))
        })
        .unwrap();
    assert!(table.get_by_id(first).is_none());
    assert!(table.get_by_id(second).is_some());
}

#[test]
fn switch_survives_rkyv_roundtrip() {
    let mut table = SwitchTable::new_transient();
    let branch = Address::from(0x401000u64);
    let id = table
        .insert(branch, |id, branch| {
            let mut switch = Switch::new(
                id,
                branch,
                SwitchModel::OffsetRelative {
                    table: table_of(4, 0),
                    base: 0x400000u64.into(),
                    signed: true,
                },
            );
            let mut case = SwitchCase::new(AddressWithContext::new(
                Address::from(0x401100u64),
                ContextSet::default(),
            ));
            case.add_label(SwitchCaseLabel::new(7));
            switch.add_case(case);
            switch.set_properties(SwitchProperties::GUARD_FOUND);
            switch.mark_truncated();
            Ok(switch)
        })
        .unwrap();

    let switch = table.get_by_id(id).unwrap().as_ref().clone();
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&switch).unwrap();
    let restored = rkyv::from_bytes::<Switch, rkyv::rancor::Error>(&bytes).unwrap();

    assert_eq!(restored, switch);
    assert_eq!(restored.case_count(), 1);
    assert_eq!(restored.cases()[0].labels(), &[SwitchCaseLabel::new(7)]);
    assert!(restored.is_truncated());
    assert!(matches!(
        restored.model(),
        SwitchModel::OffsetRelative { signed: true, .. }
    ));
}

#[test]
fn persistent_table_survives_reopen() {
    let storage = EntityStorage::new(InMemoryEntityStorage::new());
    let branch = Address::from(0x401000u64);

    {
        let mut table = SwitchTable::new(storage.clone(), 64 * 1024).unwrap();
        table
            .insert(branch, |id, branch| {
                let mut switch = Switch::new(id, branch, SwitchModel::Absolute(table_of(4, 0)));
                switch.add_case(SwitchCase::new(AddressWithContext::new(
                    Address::from(0x401100u64),
                    ContextSet::default(),
                )));
                Ok(switch)
            })
            .unwrap();
        table.flush().unwrap();
    }

    let table = SwitchTable::new(storage, 64 * 1024).unwrap();
    assert_eq!(table.len(), 1);
    let switch = table.get_by_branch(branch).unwrap();
    assert_eq!(switch.case_count(), 1);
    assert_eq!(switch.branch(), branch);
}
