use std::mem::size_of;

use super::*;
use crate::analysis::control::CancellationToken;
use crate::il::common::{IlGenerationContext, IlGenerationError, IlMetadata};
use crate::il::ecode::ssa::ECodeSsaIr;
use crate::il::pcode::PCodeIr;
use crate::types::EstimateSize;

macro_rules! external_form {
    ($name:ident, $id:literal) => {
        #[derive(Debug)]
        struct $name {
            metadata: IlMetadata,
        }

        impl EstimateSize for $name {
            fn estimate_size(&self) -> usize {
                size_of::<Self>()
            }
        }

        impl IlArtefact for $name {
            const FORM_IDENTIFIER: &str = $id;

            fn metadata(&self) -> &IlMetadata {
                &self.metadata
            }
        }
    };
}

external_form!(AcmeTaint, "acme.taint.values");
external_form!(AcmeSummary, "acme.taint.summary");
external_form!(AcmeReport, "acme.taint.report");
external_form!(AcmeDerived, "acme.taint.derived");
external_form!(ImpostorPCode, "fugue.pcode.cfg");

#[derive(Default)]
struct AcmeDerivedConverter;

impl IlConverter for AcmeDerivedConverter {
    type Input = ECodeSsaIr;
    type Output = AcmeDerived;

    fn convert(
        &mut self,
        source: &Self::Input,
        _context: &IlGenerationContext<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        Ok(AcmeDerived {
            metadata: *source.metadata(),
        })
    }
}

fn acme() -> DialectId {
    DialectId::from_static("acme.taint")
}

fn form_ids(registry: &IlRegistry) -> Vec<&str> {
    registry
        .forms()
        .map(|registration| registration.form().as_str())
        .collect()
}

#[test]
fn the_standard_registry_contains_the_built_in_forms() {
    let registry = IlRegistry::default();

    assert_eq!(
        form_ids(&registry),
        vec!["fugue.ecode.cfg", "fugue.ecode.ssa", "fugue.pcode.cfg"]
    );
    assert!(registry.forms().all(IlFormRegistration::is_persistable));
    assert_eq!(
        registry
            .form_of::<PCodeIr>()
            .map(|registration| registration.form().as_str()),
        Some("fugue.pcode.cfg")
    );
    assert!(
        registry
            .form_of::<PCodeIr>()
            .is_some_and(IlFormRegistration::is_root)
    );
}

#[test]
fn the_canonical_path_walks_to_the_root_producer() {
    let registry = IlRegistry::default();

    assert_eq!(
        registry
            .canonical_path(&ECodeSsaIr::FORM)
            .iter()
            .map(IlFormId::as_str)
            .collect::<Vec<_>>(),
        vec!["fugue.pcode.cfg", "fugue.ecode.cfg", "fugue.ecode.ssa"]
    );
    assert_eq!(
        registry
            .canonical_path(&PCodeIr::FORM)
            .iter()
            .map(IlFormId::as_str)
            .collect::<Vec<_>>(),
        vec!["fugue.pcode.cfg"]
    );
    assert!(registry.canonical_path(&AcmeTaint::FORM).is_empty());
    assert_eq!(
        registry
            .dependants(&PCodeIr::FORM)
            .map(IlFormId::as_str)
            .collect::<Vec<_>>(),
        vec!["fugue.ecode.cfg"]
    );
}

#[test]
fn an_external_dialect_registers_without_editing_core() {
    let registry = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_derived_form::<AcmeTaint>(ECodeSsaIr::FORM)
        .build()
        .expect("external registration is valid");

    let taint = registry
        .form_of::<AcmeTaint>()
        .expect("external form is registered");

    assert_eq!(taint.form().as_str(), "acme.taint.values");
    assert!(!taint.is_persistable());
    assert_eq!(taint.source(), Some(&ECodeSsaIr::FORM));
    assert_eq!(
        registry
            .canonical_path(&AcmeTaint::FORM)
            .iter()
            .map(IlFormId::as_str)
            .collect::<Vec<_>>(),
        vec![
            "fugue.pcode.cfg",
            "fugue.ecode.cfg",
            "fugue.ecode.ssa",
            "acme.taint.values"
        ]
    );
    assert_eq!(
        registry
            .dependants(&ECodeSsaIr::FORM)
            .map(IlFormId::as_str)
            .collect::<Vec<_>>(),
        vec!["acme.taint.values"]
    );
}

#[test]
fn registration_order_does_not_change_the_registry() {
    let forward = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_derived_form::<AcmeTaint>(ECodeSsaIr::FORM)
        .with_derived_form::<AcmeSummary>(AcmeTaint::FORM)
        .build()
        .expect("valid");
    let shuffled = IlRegistryBuilder::built_in()
        .with_derived_form::<AcmeSummary>(AcmeTaint::FORM)
        .with_derived_form::<AcmeTaint>(ECodeSsaIr::FORM)
        .with_dialect(acme())
        .build()
        .expect("valid");

    assert_eq!(form_ids(&forward), form_ids(&shuffled));
    assert_eq!(
        forward.dialects().collect::<Vec<_>>(),
        shuffled.dialects().collect::<Vec<_>>()
    );
    assert_eq!(
        forward.canonical_path(&AcmeSummary::FORM),
        shuffled.canonical_path(&AcmeSummary::FORM)
    );
    assert_eq!(
        forward.dependants(&AcmeTaint::FORM).collect::<Vec<_>>(),
        shuffled.dependants(&AcmeTaint::FORM).collect::<Vec<_>>()
    );
}

#[test]
fn registration_order_does_not_change_the_diagnostics() {
    let forward = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_derived_form::<AcmeTaint>(AcmeSummary::FORM)
        .with_form::<AcmeTaint>()
        .build()
        .expect_err("a duplicate registration is rejected");
    let shuffled = IlRegistryBuilder::built_in()
        .with_form::<AcmeTaint>()
        .with_derived_form::<AcmeTaint>(AcmeSummary::FORM)
        .with_dialect(acme())
        .build()
        .expect_err("a duplicate registration is rejected");

    assert_eq!(forward, shuffled);
    assert_eq!(
        forward.errors(),
        [IlRegistryError::DuplicateForm {
            form: AcmeTaint::FORM
        }]
    );
}

#[test]
fn a_form_cannot_refer_to_an_absent_dialect() {
    let errors = IlRegistryBuilder::built_in()
        .with_form::<AcmeTaint>()
        .build()
        .expect_err("the acme dialect is not registered");

    assert_eq!(
        errors.errors(),
        [IlRegistryError::AbsentDialect {
            dialect: acme(),
            form: AcmeTaint::FORM
        }]
    );
}

#[test]
fn a_dialect_without_forms_is_rejected() {
    let errors = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .build()
        .expect_err("an unused dialect is rejected");

    assert_eq!(
        errors.errors(),
        [IlRegistryError::UnusedDialect { dialect: acme() }]
    );
}

#[test]
fn a_recipe_cannot_name_an_absent_source() {
    let errors = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_derived_form::<AcmeTaint>(AcmeSummary::FORM)
        .build()
        .expect_err("the source form is not registered");

    assert_eq!(
        errors.errors(),
        [IlRegistryError::AbsentRecipeSource {
            form: AcmeTaint::FORM,
            source_form: AcmeSummary::FORM
        }]
    );
}

#[test]
fn duplicate_registrations_are_rejected() {
    let errors = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_dialect(acme())
        .with_form::<AcmeTaint>()
        .with_form::<AcmeTaint>()
        .build()
        .expect_err("duplicates are rejected");

    assert_eq!(
        errors.errors(),
        [
            IlRegistryError::DuplicateDialect { dialect: acme() },
            IlRegistryError::DuplicateForm {
                form: AcmeTaint::FORM
            }
        ]
    );
}

#[test]
fn built_in_forms_cannot_be_replaced_by_an_external_registration() {
    let errors = IlRegistryBuilder::built_in()
        .with_form::<ImpostorPCode>()
        .build()
        .expect_err("a built-in form cannot be shadowed");

    assert_eq!(
        errors.errors(),
        [IlRegistryError::ReservedDialect {
            dialect: PCODE_DIALECT
        }]
    );
    assert!(
        IlRegistry::default()
            .form(&PCodeIr::FORM)
            .is_some_and(IlFormRegistration::is_persistable)
    );
}

#[test]
fn a_recipe_cycle_names_only_the_forms_on_the_cycle() {
    let errors = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_derived_form::<AcmeReport>(AcmeTaint::FORM)
        .with_derived_form::<AcmeTaint>(AcmeSummary::FORM)
        .with_derived_form::<AcmeSummary>(AcmeTaint::FORM)
        .build()
        .expect_err("the recipe graph is cyclic");

    assert_eq!(
        errors.errors(),
        [
            IlRegistryError::RecipeCycle {
                form: AcmeSummary::FORM
            },
            IlRegistryError::RecipeCycle {
                form: AcmeTaint::FORM
            }
        ]
    );
}

#[test]
fn aggregated_errors_render_every_problem() {
    let errors = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_dialect(acme())
        .build()
        .expect_err("duplicates are rejected");

    assert_eq!(
        errors.to_string(),
        "the IL registry is invalid\n  dialect `acme.taint` is registered more than once\n  \
         dialect `acme.taint` is registered but has no forms"
    );
}

#[test]
fn a_registered_conversion_dispatches_without_a_core_match_arm() {
    let registry = IlRegistryBuilder::built_in()
        .with_dialect(acme())
        .with_converted_form::<AcmeDerivedConverter>()
        .build()
        .expect("a typed conversion registers");

    let registration = registry
        .form_of::<AcmeDerived>()
        .expect("the conversion is registered");

    assert_eq!(registration.source(), Some(&ECodeSsaIr::FORM));
    assert!(matches!(
        registration.recipe(),
        Some(IlRecipe::Converter(_))
    ));
    assert_eq!(
        registry
            .canonical_path(&AcmeDerived::FORM)
            .iter()
            .map(IlFormId::as_str)
            .collect::<Vec<_>>(),
        vec![
            "fugue.pcode.cfg",
            "fugue.ecode.cfg",
            "fugue.ecode.ssa",
            "acme.taint.derived"
        ]
    );
    assert!(matches!(
        registry
            .form(&PCodeIr::FORM)
            .and_then(IlFormRegistration::recipe),
        Some(IlRecipe::Producer(_))
    ));
}
