use fugue_core::ir::{Address, Switch, SwitchModel};
use fugue_core::project::Project;
use fugue_core::storage::AddressSpaceId;

#[test]
fn rejecting_switch_insertion_discards_the_switch() -> Result<(), Box<dyn std::error::Error>> {
    let mut project = Project::from_file_transient("tests/ls.elf")?;
    let branch = Address::new(AddressSpaceId::new(1), 0x1000u64);

    {
        let mut transaction = project.transaction("test");
        transaction.add_switch(branch, |id, branch| {
            Switch::new(id, branch, SwitchModel::Explicit)
        })?;
        assert!(transaction.switch_at(branch).is_some());
        drop(transaction);
    }

    assert!(project.switches().get_by_branch(branch).is_none());
    Ok(())
}
