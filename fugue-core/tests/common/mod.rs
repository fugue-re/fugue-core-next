use std::error::Error;
use std::io;

use fugue_core::ir::{Address, IncompleteCodeBlock, IncompleteFunction};
use fugue_core::lifter::ContextSet;
use fugue_core::project::Project;
use fugue_core::storage::segments::DEFAULT_SPACE_ID;

pub fn one_block_function(entry: Address, len: usize) -> IncompleteFunction {
    let mut function = IncompleteFunction::new(entry);
    function.push_block(
        IncompleteCodeBlock::try_new(entry, len, Vec::new(), ContextSet::default())
            .expect("test block length must fit"),
    );
    function
}

pub fn writable_address(project: &Project, minimum_size: u64) -> Result<Address, Box<dyn Error>> {
    project
        .segments()
        .iter_views(DEFAULT_SPACE_ID)?
        .find(|view| view.properties().is_writable() && view.size() >= minimum_size)
        .map(|view| view.start())
        .ok_or_else(|| io::Error::other("fixture writable segment missing").into())
}
