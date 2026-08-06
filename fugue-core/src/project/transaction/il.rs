use std::any::Any;

use smallvec::SmallVec;

use super::ProjectTransaction;
use crate::il::common::{IlError, IlFormId, PersistableIl};
use crate::il::registry::IlFormRegistration;
use crate::ir::{AddressRange, FunctionId};
use crate::project::ProjectError;

impl ProjectTransaction<'_> {
    pub(crate) fn materialise_erased(
        &mut self,
        form: &IlFormId,
        value: Box<dyn Any + Send + Sync>,
    ) -> Result<(), ProjectError> {
        if self.changes.semantic() {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        let admit = self
            .registry
            .form(form)
            .and_then(IlFormRegistration::admit)
            .ok_or_else(|| IlError::dialect_unavailable(form.as_str()))?;

        Ok(admit(
            &mut self.il_staging,
            &self.project.storage,
            value,
            self.project.semantic_revision(),
        )?)
    }

    pub fn replace_lifted<T>(&mut self, mut ir: T) -> Result<(), ProjectError>
    where
        T: PersistableIl,
    {
        if self.changes.semantic() {
            return Err(IlError::publish_after_semantic_mutation().into());
        }

        ir.metadata_mut()
            .set_input_revision(self.project.semantic_revision());

        self.il_staging.replace(&self.project.storage, ir)?;

        Ok(())
    }

    pub fn remove_lifted<T: PersistableIl>(
        &mut self,
        function: FunctionId,
    ) -> Result<bool, ProjectError> {
        Ok(self
            .il_staging
            .remove::<T>(&self.project.storage, function)?
            .is_some())
    }

    pub(crate) fn remove_lifted_by_form(
        &mut self,
        function: FunctionId,
        form: &IlFormId,
    ) -> Result<bool, ProjectError> {
        Ok(self
            .il_staging
            .remove_form(&self.project.storage, function, form)?)
    }

    pub fn remove_lifted_descendants(
        &mut self,
        function: FunctionId,
        first_invalid: &IlFormId,
    ) -> Result<usize, ProjectError> {
        let mut removed = 0usize;

        let registry = self.registry.clone();
        for form in registry.descendants(first_invalid) {
            if self.remove_lifted_by_form(function, form)? {
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn remove_lifted_descendants_in_range(
        &mut self,
        range: &AddressRange,
        first_invalid: &IlFormId,
    ) -> Result<usize, ProjectError> {
        let functions = self
            .project
            .functions
            .overlaps(&self.project.blocks, range)
            .collect::<SmallVec<[_; 8]>>();
        let mut removed = 0usize;

        for function in functions {
            removed += self.remove_lifted_descendants(function, first_invalid)?;
        }

        Ok(removed)
    }
}
