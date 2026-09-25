use smallvec::SmallVec;

use super::ProjectTransaction;
use crate::ir::{
    Address, AddressRange, AddressRangeSet, FunctionId, Reference, ReferenceKind,
    ReferenceProvenance, Switch, SwitchId, SwitchTableError,
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
        let existing = self
            .switch_staging
            .get_by_branch(&self.project.switches, branch)?
            .map(|switch| switch.as_ref().clone());
        let id = match existing {
            Some(ref switch) => switch.id(),
            None => self.switch_staging.reserve_id(&self.project.switches),
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
        self.switch_staging.insert(switch);
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
        let Some(mut switch) = self
            .switch_staging
            .get_by_branch(&self.project.switches, branch)?
            .map(|switch| switch.as_ref().clone())
        else {
            return Ok(None);
        };
        let result = f(&mut switch);
        switch.set_function(function.unwrap_or(FunctionId::INVALID));
        self.synchronise_switch_references(&switch)?;
        self.switch_staging.insert(switch);
        Ok(Some(result))
    }

    pub fn remove_switch(&mut self, branch: Address) -> Result<bool, ProjectError> {
        let Some(switch) = self.switch_staging.remove(&self.project.switches, branch)? else {
            return Ok(false);
        };

        self.replace_switch_references(switch.id(), branch, [])?;
        Ok(true)
    }

    pub(crate) fn remove_switches_of_function(
        &mut self,
        function: FunctionId,
    ) -> Result<(), ProjectError> {
        for branch in self
            .switch_staging
            .branches_for_function(&self.project.switches, function)
        {
            self.remove_switch(branch)?;
        }

        Ok(())
    }

    fn synchronise_switch_references(&mut self, switch: &Switch) -> Result<bool, ProjectError> {
        let references = switch.derived_references().collect::<SmallVec<[_; 8]>>();
        self.replace_switch_references(switch.id(), switch.branch(), references)
    }

    fn replace_switch_references(
        &mut self,
        id: SwitchId,
        branch: Address,
        references: impl IntoIterator<Item = Reference>,
    ) -> Result<bool, ProjectError> {
        let mut coverage = AddressRangeSet::new();
        coverage.insert_range(AddressRange::point(branch));

        let (flow, data) = references
            .into_iter()
            .partition::<Vec<_>, _>(Reference::is_flow);
        let provenance = ReferenceProvenance::Switch(id);
        let flow_changed = self.replace_derived_references(
            coverage.clone(),
            ReferenceKind::Flow,
            provenance,
            flow,
        )?;
        let data_changed =
            self.replace_derived_references(coverage, ReferenceKind::Data, provenance, data)?;
        Ok(flow_changed || data_changed)
    }
}
