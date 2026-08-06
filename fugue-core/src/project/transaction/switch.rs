use std::collections::BTreeSet;

use smallvec::SmallVec;

use super::ProjectTransaction;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, Reference, ReferenceKind, Switch, SwitchId,
    SwitchTableError,
};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub fn add_switch<F>(&mut self, branch: Address, f: F) -> Result<SwitchId, ProjectError>
    where
        F: FnOnce(SwitchId, Address) -> Switch,
    {
        let function = self
            .project
            .functions
            .staged_unique_function_containing_address(
                &self.project.blocks,
                &self.function_staging,
                branch,
            )?;
        let existing = self.staged_switch(branch)?;
        let id = match existing {
            Some(ref switch) => switch.id(),
            None => {
                let id = self
                    .project
                    .switches
                    .pending_id(self.switch_reservations.len());
                self.switch_reservations.push(id);
                id
            }
        };
        let switch = f(id, branch);
        if switch.branch() != branch {
            return Err(SwitchTableError::AddressMismatch.into());
        }
        let switch = match function {
            Some(function) => switch.with_function(function),
            None => switch,
        };
        self.synchronise_switch_references(&switch)?;
        self.staged_switches.insert(branch, Some(switch));
        Ok(id)
    }

    pub fn modify_switch<R>(
        &mut self,
        branch: Address,
        f: impl FnOnce(&mut Switch) -> R,
    ) -> Result<Option<R>, ProjectError> {
        let function = self
            .project
            .functions
            .staged_unique_function_containing_address(
                &self.project.blocks,
                &self.function_staging,
                branch,
            )?;
        let Some(mut switch) = self.staged_switch(branch)? else {
            return Ok(None);
        };
        let result = f(&mut switch);
        switch.set_function(function.unwrap_or(FunctionId::INVALID));
        self.synchronise_switch_references(&switch)?;
        self.staged_switches.insert(branch, Some(switch));
        Ok(Some(result))
    }

    pub fn remove_switch(&mut self, branch: Address) -> Result<bool, ProjectError> {
        let Some(switch) = self.staged_switch(branch)? else {
            return Ok(false);
        };

        self.replace_switch_references(branch, [])?;
        if self.project.switches.try_get_by_branch(branch)?.is_some() {
            self.staged_switches.insert(branch, None);
        } else {
            self.staged_switches.remove(&branch);
            self.cancelled_switches.push(switch.id());
        }
        Ok(true)
    }

    pub(crate) fn remove_switches_of_function(
        &mut self,
        function: FunctionId,
    ) -> Result<(), ProjectError> {
        let mut branches = self
            .project
            .switches
            .branches_of_function(function)
            .collect::<BTreeSet<_>>();
        for (&branch, switch) in &self.staged_switches {
            match switch {
                Some(switch) if switch.function() == function => {
                    branches.insert(branch);
                }
                Some(_) | None => {
                    branches.remove(&branch);
                }
            }
        }

        for branch in branches {
            self.remove_switch(branch)?;
        }

        Ok(())
    }

    fn synchronise_switch_references(&mut self, switch: &Switch) -> Result<bool, ProjectError> {
        let references = switch.derived_references().collect::<SmallVec<[_; 8]>>();
        self.replace_switch_references(switch.branch(), references)
    }

    fn staged_switch(&self, branch: Address) -> Result<Option<Switch>, ProjectError> {
        match self.staged_switches.get(&branch) {
            Some(switch) => Ok(switch.clone()),
            None => Ok(self
                .project
                .switches
                .try_get_by_branch(branch)?
                .map(|switch| switch.as_ref().clone())),
        }
    }

    fn replace_switch_references(
        &mut self,
        branch: Address,
        references: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(branch));

        let (flow, data) = references
            .into_iter()
            .partition::<Vec<_>, _>(Reference::is_flow);
        let flow_changed =
            self.replace_derived_references(coverage.clone(), ReferenceKind::Flow, flow)?;
        let data_changed = self.replace_derived_references(coverage, ReferenceKind::Data, data)?;
        Ok(flow_changed || data_changed)
    }
}
