use fugue_core::engine::AnalysisEngine;
use fugue_core::engine::change::{ChangeKinds, ChangeRecord};
use fugue_core::ir::{Address, AddressTable, Switch, SwitchModel};
use fugue_core::loader::Loader;
use fugue_core::project::Project;

fn absolute(model_table: Address) -> SwitchModel {
    SwitchModel::Absolute(AddressTable::new(model_table, 4).with_element_count(3))
}

#[test]
fn query_reader_exposes_switches() -> Result<(), Box<dyn std::error::Error>> {
    let loader = Loader::from_file("tests/ls.elf")?;
    let mut project = Project::new_transient(&loader)?;

    let branch_a = Address::from(0x40_1000u64);
    let branch_b = Address::from(0x40_1100u64);
    {
        let mut transaction = project.transaction("switches");
        transaction.add_switch(branch_a, |id, branch| {
            Switch::new(id, branch, absolute(Address::from(0x40_2000u64)))
        })?;
        transaction.add_switch(branch_b, |id, branch| {
            Switch::new(id, branch, SwitchModel::Explicit)
        })?;
        transaction.commit()?;
    }

    let engine = AnalysisEngine::new(project)?;
    let reader = engine.query_reader()?;

    let record = reader.switch_at(branch_a)?.expect("switch at branch_a");
    assert_eq!(record.branch(), branch_a);
    assert!(matches!(record.switch().model(), SwitchModel::Absolute(_)));
    assert!(reader.switch_at(Address::from(0x99_9999u64))?.is_none());

    let all = reader.switches().collect::<Result<Vec<_>, _>>()?;
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].branch(), branch_a);
    assert_eq!(all[1].branch(), branch_b);

    let first = reader.switch_page(None, 1)?;
    assert_eq!(first.entries().len(), 1);
    assert_eq!(first.entries()[0].branch(), branch_a);
    let cursor = first.next_cursor().cloned();
    assert_eq!(cursor, Some(branch_a));

    let second = reader.switch_page(cursor, 1)?;
    assert_eq!(second.entries().len(), 1);
    assert_eq!(second.entries()[0].branch(), branch_b);

    Ok(())
}

#[test]
fn switch_change_records_classify_under_switches_group() {
    let branch = Address::from(0x40_1000u64);

    assert_eq!(
        ChangeRecord::SwitchAdded { branch }.kind(),
        ChangeKinds::SWITCH_ADDED
    );
    assert_eq!(
        ChangeRecord::SwitchRemoved { branch }.kind(),
        ChangeKinds::SWITCH_REMOVED
    );
    assert!(ChangeKinds::SWITCHES.contains(ChangeKinds::SWITCH_ADDED));
    assert!(ChangeKinds::SWITCHES.contains(ChangeKinds::SWITCH_REMOVED));
    assert!(!ChangeKinds::SWITCHES.intersects(ChangeKinds::REFERENCES));

    let ranges = ChangeRecord::SwitchAdded { branch }.ranges();
    assert_eq!(ranges.len(), 1);
    assert!(ranges[0].contains(branch.raw_address()));
}
