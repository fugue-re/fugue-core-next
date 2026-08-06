use std::any::{Any, TypeId};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, LazyLock};

use rustc_hash::FxHashMap;
use thiserror::Error as ThisError;

use crate::extension::{self, Registration};
use crate::il::common::{
    DialectId, IlArtefact, IlConverter, IlError, IlFormId, IlProducer, IlSchemaVersion,
    PersistableIl,
};
use crate::il::ecode::PCodeToECode;
use crate::il::ecode::ssa::ECodeToSsa;
use crate::il::pcode::PCodeCanonicaliser;
use crate::il::storage::{IlPersist, IlStaging, IlStorageError};
use crate::ir::FunctionId;
use crate::storage::StorageContainer;
use crate::types::EstimateSize;
use crate::types::common::Revision;

mod runtime;

use runtime::IlRecipe;
pub(crate) use runtime::{GeneratedArtefact, IlGenerationSession};

const PCODE_DIALECT: DialectId = DialectId::from_static("fugue.pcode");
const ECODE_DIALECT: DialectId = DialectId::from_static("fugue.ecode");

#[derive(Debug, ThisError, PartialEq, Eq, PartialOrd, Ord)]
pub enum IlRegistryError {
    #[error("form `{form}` refers to dialect `{dialect}`, which is not registered")]
    AbsentDialect { dialect: DialectId, form: IlFormId },
    #[error("recipe for form `{form}` names source `{source_form}`, which is not registered")]
    AbsentRecipeSource {
        form: IlFormId,
        source_form: IlFormId,
    },
    #[error("dialect `{dialect}` is registered more than once")]
    DuplicateDialect { dialect: DialectId },
    #[error("form `{form}` is registered more than once")]
    DuplicateForm { form: IlFormId },
    #[error("form `{form}` is its own canonical ancestor")]
    RecipeCycle { form: IlFormId },
    #[error("`{dialect}` is reserved for first-party dialects")]
    ReservedDialect { dialect: DialectId },
    #[error("dialect `{dialect}` is registered but has no forms")]
    UnusedDialect { dialect: DialectId },
}

#[derive(Debug, PartialEq, Eq)]
pub struct IlRegistryErrors {
    errors: Vec<IlRegistryError>,
}

impl IlRegistryErrors {
    fn new(mut errors: Vec<IlRegistryError>) -> Self {
        errors.sort();
        errors.dedup();
        Self { errors }
    }

    pub fn errors(&self) -> &[IlRegistryError] {
        &self.errors
    }
}

impl fmt::Display for IlRegistryErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the IL registry is invalid")?;
        for error in &self.errors {
            write!(f, "\n  {error}")?;
        }
        Ok(())
    }
}

impl Error for IlRegistryErrors {}

#[derive(Debug)]
pub struct IlDialectRegistration {
    identifier: &'static str,
    dialect: DialectId,
}

impl IlDialectRegistration {
    pub const fn new(identifier: &'static str) -> Self {
        Self {
            identifier,
            dialect: DialectId::from_static(identifier),
        }
    }

    pub fn dialect(&self) -> &DialectId {
        &self.dialect
    }
}

impl Registration for IlDialectRegistration {
    fn name(&self) -> &'static str {
        self.identifier
    }
}

extension::collect!(IlDialectRegistration);

pub(crate) type IlProduced = Box<dyn Any + Send + Sync>;

pub(crate) type IlSizeFn = fn(&(dyn Any + Send + Sync)) -> Result<usize, IlError>;

fn size_erased<T: IlArtefact>(artefact: &(dyn Any + Send + Sync)) -> Result<usize, IlError> {
    artefact
        .downcast_ref::<T>()
        .map(EstimateSize::estimate_size)
        .ok_or_else(|| IlError::mismatched_artefact(T::FORM))
}

pub(crate) type IlLoadFn =
    fn(&StorageContainer, FunctionId, Revision) -> Result<Option<IlProduced>, IlStorageError>;

fn load_erased<T: PersistableIl>(
    storage: &StorageContainer,
    function: FunctionId,
    input_revision: Revision,
) -> Result<Option<IlProduced>, IlStorageError> {
    Ok(T::load_current(storage, function, input_revision)?
        .map(|artefact| Box::new(artefact) as IlProduced))
}

pub(crate) type IlAdmitFn =
    fn(&mut IlStaging, &StorageContainer, IlProduced, Revision) -> Result<(), IlStorageError>;

fn admit_erased<T: PersistableIl>(
    staging: &mut IlStaging,
    storage: &StorageContainer,
    value: IlProduced,
    input_revision: Revision,
) -> Result<(), IlStorageError> {
    let mut artefact = *value
        .downcast::<T>()
        .map_err(|_| IlError::mismatched_source(T::FORM))?;
    artefact.metadata_mut().set_input_revision(input_revision);

    Ok(staging.replace(storage, artefact)?)
}

#[derive(Debug)]
pub struct IlFormRegistration {
    identifier: &'static str,
    form: IlFormId,
    type_id: TypeId,
    schema: Option<IlSchemaVersion>,
    source: Option<IlFormId>,
    recipe: Option<IlRecipe>,
    admit: Option<IlAdmitFn>,
    load: Option<IlLoadFn>,
    size: IlSizeFn,
}

impl IlFormRegistration {
    pub const fn of<T: IlArtefact>() -> Self {
        Self::new::<T>(None, None)
    }

    pub const fn root<T: IlProducer>() -> Self {
        Self::new::<T::Output>(None, Some(IlRecipe::producer::<T>()))
    }

    pub const fn derived<T: IlConverter>() -> Self {
        Self::new::<T::Output>(Some(T::Input::FORM), Some(IlRecipe::converter::<T>()))
    }

    pub const fn persistable<T: PersistableIl>() -> Self {
        Self::new_persistable::<T>(None, None)
    }

    pub const fn persistable_root<T: IlProducer>() -> Self
    where
        T::Output: PersistableIl,
    {
        Self::new_persistable::<T::Output>(None, Some(IlRecipe::producer::<T>()))
    }

    pub const fn persistable_derived<T: IlConverter>() -> Self
    where
        T::Output: PersistableIl,
    {
        Self::new_persistable::<T::Output>(Some(T::Input::FORM), Some(IlRecipe::converter::<T>()))
    }

    const fn new<T: IlArtefact>(source: Option<IlFormId>, recipe: Option<IlRecipe>) -> Self {
        Self {
            identifier: T::FORM_IDENTIFIER,
            form: T::FORM,
            type_id: TypeId::of::<T>(),
            schema: None,
            source,
            recipe,
            admit: None,
            load: None,
            size: size_erased::<T>,
        }
    }

    const fn new_persistable<T: PersistableIl>(
        source: Option<IlFormId>,
        recipe: Option<IlRecipe>,
    ) -> Self {
        Self {
            identifier: T::FORM_IDENTIFIER,
            form: T::FORM,
            type_id: TypeId::of::<T>(),
            schema: Some(T::SCHEMA),
            source,
            recipe,
            admit: Some(admit_erased::<T>),
            load: Some(load_erased::<T>),
            size: size_erased::<T>,
        }
    }

    pub(crate) fn admit(&self) -> Option<IlAdmitFn> {
        self.admit
    }

    pub(crate) fn load(&self) -> Option<IlLoadFn> {
        self.load
    }

    pub(crate) fn size(&self) -> IlSizeFn {
        self.size
    }

    fn recipe(&self) -> Option<IlRecipe> {
        self.recipe
    }

    pub fn form(&self) -> &IlFormId {
        &self.form
    }

    pub fn schema(&self) -> Option<IlSchemaVersion> {
        self.schema
    }

    pub fn source(&self) -> Option<&IlFormId> {
        self.source.as_ref()
    }

    pub fn is_persistable(&self) -> bool {
        self.schema.is_some()
    }

    pub fn is_root(&self) -> bool {
        self.source.is_none()
    }
}

impl Registration for IlFormRegistration {
    fn name(&self) -> &'static str {
        self.identifier
    }
}

extension::collect!(IlFormRegistration);

#[derive(Debug)]
pub struct IlRegistryBuilder {
    dialects: BTreeSet<DialectId>,
    forms: BTreeMap<IlFormId, IlFormRegistration>,
    duplicates: BTreeSet<IlFormId>,
    errors: Vec<IlRegistryError>,
}

impl IlRegistryBuilder {
    pub fn built_in() -> Self {
        let mut builder = Self {
            dialects: BTreeSet::new(),
            forms: BTreeMap::new(),
            duplicates: BTreeSet::new(),
            errors: Vec::new(),
        };
        builder.insert_dialect(PCODE_DIALECT);
        builder.insert_dialect(ECODE_DIALECT);
        builder.insert_form(IlFormRegistration::persistable_root::<PCodeCanonicaliser>());
        builder.insert_form(IlFormRegistration::persistable_derived::<PCodeToECode>());
        builder.insert_form(IlFormRegistration::persistable_derived::<ECodeToSsa>());
        builder
    }

    pub fn standard() -> Self {
        let mut builder = Self::built_in();
        for registration in extension::iter::<IlDialectRegistration>() {
            let dialect = registration.dialect().clone();
            if dialect.is_reserved() {
                builder
                    .errors
                    .push(IlRegistryError::ReservedDialect { dialect });
                continue;
            }
            builder.insert_dialect(dialect);
        }
        for registration in extension::iter::<IlFormRegistration>() {
            if registration.form().dialect().is_reserved() {
                builder.errors.push(IlRegistryError::ReservedDialect {
                    dialect: registration.form().dialect(),
                });
                continue;
            }
            builder.insert_form(IlFormRegistration {
                identifier: registration.identifier,
                form: registration.form.clone(),
                type_id: registration.type_id,
                schema: registration.schema,
                source: registration.source.clone(),
                recipe: registration.recipe,
                admit: registration.admit,
                load: registration.load,
                size: registration.size,
            });
        }
        builder
    }

    pub fn with_dialect(mut self, dialect: DialectId) -> Self {
        if dialect.is_reserved() {
            self.errors
                .push(IlRegistryError::ReservedDialect { dialect });
            return self;
        }
        self.insert_dialect(dialect);
        self
    }

    pub fn with_form<T: IlArtefact>(self) -> Self {
        self.register(IlFormRegistration::of::<T>())
    }

    pub fn with_produced_form<T: IlProducer>(self) -> Self {
        self.register(IlFormRegistration::root::<T>())
    }

    pub fn with_converted_form<T: IlConverter>(self) -> Self {
        self.register(IlFormRegistration::derived::<T>())
    }

    pub fn with_derived_form<T: IlArtefact>(self, source: IlFormId) -> Self {
        self.register(IlFormRegistration::new::<T>(Some(source), None))
    }

    pub fn build(self) -> Result<IlRegistry, IlRegistryErrors> {
        let Self {
            dialects,
            forms,
            duplicates,
            mut errors,
        } = self;

        let mut populated = BTreeSet::new();
        for registration in forms.values() {
            let dialect = registration.form().dialect();
            if dialects.contains(&dialect) {
                populated.insert(dialect);
            } else {
                errors.push(IlRegistryError::AbsentDialect {
                    dialect,
                    form: registration.form().clone(),
                });
            }

            if duplicates.contains(registration.form()) {
                continue;
            }

            if let Some(source) = registration.source()
                && !forms.contains_key(source)
            {
                errors.push(IlRegistryError::AbsentRecipeSource {
                    form: registration.form().clone(),
                    source_form: source.clone(),
                });
            }
        }

        for dialect in dialects.difference(&populated) {
            errors.push(IlRegistryError::UnusedDialect {
                dialect: dialect.clone(),
            });
        }

        Self::report_recipe_cycles(&forms, &duplicates, &mut errors);

        if !errors.is_empty() {
            return Err(IlRegistryErrors::new(errors));
        }

        let forms_by_type = forms
            .values()
            .map(|registration| (registration.type_id, registration.form().clone()))
            .collect();
        let mut dependants = BTreeMap::<IlFormId, Vec<IlFormId>>::new();
        for registration in forms.values() {
            if let Some(source) = registration.source() {
                dependants
                    .entry(source.clone())
                    .or_default()
                    .push(registration.form().clone());
            }
        }
        let canonical_paths = forms
            .keys()
            .map(|form| (form.clone(), Self::canonical_path(&forms, form)))
            .collect();
        let descendants = forms
            .keys()
            .map(|form| (form.clone(), Self::descendants(&dependants, form)))
            .collect();

        Ok(IlRegistry {
            dialects: dialects.into_iter().collect(),
            forms,
            forms_by_type,
            dependants,
            canonical_paths,
            descendants,
        })
    }

    fn register(mut self, registration: IlFormRegistration) -> Self {
        let dialect = registration.form().dialect();
        if dialect.is_reserved() {
            self.errors
                .push(IlRegistryError::ReservedDialect { dialect });
            return self;
        }
        self.insert_form(registration);
        self
    }

    fn insert_dialect(&mut self, dialect: DialectId) {
        if !self.dialects.insert(dialect.clone()) {
            self.errors
                .push(IlRegistryError::DuplicateDialect { dialect });
        }
    }

    fn insert_form(&mut self, registration: IlFormRegistration) {
        let form = registration.form().clone();
        if self.forms.insert(form.clone(), registration).is_some() {
            self.errors
                .push(IlRegistryError::DuplicateForm { form: form.clone() });
            self.duplicates.insert(form);
        }
    }

    fn descendants(
        dependants: &BTreeMap<IlFormId, Vec<IlFormId>>,
        form: &IlFormId,
    ) -> Vec<IlFormId> {
        let mut ordered = vec![form.clone()];
        let mut index = 0;
        while index < ordered.len() {
            if let Some(children) = dependants.get(&ordered[index]) {
                for child in children {
                    if !ordered.contains(child) {
                        ordered.push(child.clone());
                    }
                }
            }
            index += 1;
        }
        ordered
    }

    fn canonical_path(
        forms: &BTreeMap<IlFormId, IlFormRegistration>,
        form: &IlFormId,
    ) -> Vec<IlFormId> {
        let mut path = Vec::new();
        let mut current = forms.get(form);
        while let Some(registration) = current {
            path.push(registration.form().clone());
            current = registration.source().and_then(|source| forms.get(source));
        }
        path.reverse();
        path
    }

    fn report_recipe_cycles(
        forms: &BTreeMap<IlFormId, IlFormRegistration>,
        duplicates: &BTreeSet<IlFormId>,
        errors: &mut Vec<IlRegistryError>,
    ) {
        let mut settled = BTreeSet::<&IlFormId>::new();
        let mut visited = BTreeMap::<&IlFormId, usize>::new();
        let mut walk = Vec::<&IlFormId>::new();
        for start in forms.keys().filter(|form| !duplicates.contains(*form)) {
            walk.clear();
            visited.clear();
            let mut current = Some(start);
            while let Some(form) = current {
                if settled.contains(form) {
                    break;
                }
                if let Some(&entry) = visited.get(form) {
                    errors.extend(
                        walk[entry..]
                            .iter()
                            .map(|form| IlRegistryError::RecipeCycle {
                                form: (*form).clone(),
                            }),
                    );
                    break;
                }
                visited.insert(form, walk.len());
                walk.push(form);
                current = forms.get(form).and_then(IlFormRegistration::source);
            }
            settled.extend(walk.iter().copied());
        }
    }
}

#[derive(Debug)]
pub struct IlRegistry {
    dialects: Vec<DialectId>,
    forms: BTreeMap<IlFormId, IlFormRegistration>,
    forms_by_type: FxHashMap<TypeId, IlFormId>,
    dependants: BTreeMap<IlFormId, Vec<IlFormId>>,
    canonical_paths: BTreeMap<IlFormId, Vec<IlFormId>>,
    descendants: BTreeMap<IlFormId, Vec<IlFormId>>,
}

static STANDARD: LazyLock<Arc<IlRegistry>> = LazyLock::new(|| Arc::new(IlRegistry::default()));

impl Default for IlRegistry {
    fn default() -> Self {
        match IlRegistryBuilder::standard().build() {
            Ok(registry) => registry,
            Err(errors) => panic!("{errors}"),
        }
    }
}

impl IlRegistry {
    pub fn standard() -> &'static Arc<Self> {
        &STANDARD
    }

    pub fn descendants(&self, form: &IlFormId) -> &[IlFormId] {
        self.descendants.get(form).map_or(&[], Vec::as_slice)
    }

    pub fn dialects(&self) -> impl Iterator<Item = &DialectId> {
        self.dialects.iter()
    }

    pub fn forms(&self) -> impl Iterator<Item = &IlFormRegistration> {
        self.forms.values()
    }

    pub fn form(&self, form: &IlFormId) -> Option<&IlFormRegistration> {
        self.forms.get(form)
    }

    pub fn form_of<T: IlArtefact>(&self) -> Option<&IlFormRegistration> {
        let form = self.forms_by_type.get(&TypeId::of::<T>())?;
        self.forms.get(form)
    }

    pub(crate) fn registered_form<T: IlArtefact>(&self) -> Result<&IlFormRegistration, IlError> {
        let registration = self
            .form(&T::FORM)
            .ok_or_else(|| IlError::unregistered_form(T::FORM))?;
        if registration.type_id != TypeId::of::<T>() {
            return Err(IlError::mismatched_artefact(T::FORM));
        }
        Ok(registration)
    }

    pub fn contains(&self, form: &IlFormId) -> bool {
        self.forms.contains_key(form)
    }

    pub fn dependants(&self, form: &IlFormId) -> impl Iterator<Item = &IlFormId> {
        self.dependants.get(form).into_iter().flatten()
    }

    pub fn canonical_path(&self, form: &IlFormId) -> &[IlFormId] {
        self.canonical_paths.get(form).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod test;
