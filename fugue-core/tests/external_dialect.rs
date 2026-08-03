use std::mem::size_of;

use fugue_core::engine::AnalysisEngineConfig;
use fugue_core::extension::submit;
use fugue_core::il::common::{DialectId, IlAnalysis, IlArtefact, IlMetadata, IlRewrite};
use fugue_core::il::ecode::ECodeIr as CoreECodeIr;
use fugue_core::il::registry::{
    IlDialectRegistration, IlFormRegistration, IlRegistryBuilder, IlRegistryError,
};
use fugue_core::ir::FunctionId;
use fugue_core::queries::QueryableIl;
use fugue_core::types::EstimateSize;

#[derive(Debug)]
struct AcmeSummary {
    metadata: IlMetadata,
    calls: Vec<FunctionId>,
}

impl AcmeSummary {
    fn new(metadata: IlMetadata, calls: Vec<FunctionId>) -> Self {
        Self { metadata, calls }
    }

    fn calls(&self) -> &[FunctionId] {
        &self.calls
    }
}

impl EstimateSize for AcmeSummary {
    fn estimate_size(&self) -> usize {
        size_of::<Self>().saturating_add(
            self.calls
                .capacity()
                .saturating_mul(size_of::<FunctionId>()),
        )
    }
}

impl IlArtefact for AcmeSummary {
    const FORM_IDENTIFIER: &str = "acme.summary.calls";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

submit! { IlDialectRegistration::new("acme.summary") }
submit! { IlFormRegistration::of::<AcmeSummary>() }

impl QueryableIl for AcmeSummary {}

struct CallCount(usize);

impl IlAnalysis<AcmeSummary> for CallCount {
    fn analyse(ir: &AcmeSummary) -> Self {
        Self(ir.calls().len())
    }
}

struct DeduplicateCalls;

impl IlRewrite<AcmeSummary> for DeduplicateCalls {
    fn rewrite(&mut self, ir: &mut AcmeSummary) {
        ir.calls.dedup();
    }
}

#[test]
fn an_external_non_cfg_artefact_implements_the_base_contract() {
    let function = FunctionId::default();
    let summary = AcmeSummary::new(IlMetadata::new(function, 7u64), vec![function]);

    assert_eq!(AcmeSummary::FORM.as_str(), "acme.summary.calls");
    assert_eq!(
        AcmeSummary::FORM.dialect(),
        DialectId::from_static("acme.summary")
    );
    assert!(!AcmeSummary::FORM.dialect().is_reserved());
    assert_eq!(summary.metadata().function(), function);
    assert_eq!(summary.metadata().input_revision().value(), 7);
    assert_eq!(summary.calls(), &[function]);
    assert!(summary.estimate_size() >= size_of::<AcmeSummary>());
}

#[test]
fn an_external_artefact_drives_the_analysis_and_rewrite_hooks() {
    let function = FunctionId::default();
    let mut summary = AcmeSummary::new(
        IlMetadata::new(function, 0u64),
        vec![function, function, function],
    );

    assert_eq!(summary.analyse::<CallCount>().0, 3);

    summary.rewrite(DeduplicateCalls);

    assert_eq!(summary.calls(), &[function]);
    assert_eq!(summary.analyse::<CallCount>().0, 1);
}

#[test]
fn an_external_form_registers_through_the_extension_mechanism() {
    let registry = IlRegistryBuilder::standard()
        .build()
        .expect("the submitted registration is valid");

    let registration = registry
        .form_of::<AcmeSummary>()
        .expect("the submitted form is registered");
    assert_eq!(registration.form(), &AcmeSummary::FORM);
    assert!(registration.is_root());
    assert!(!registration.is_persistable());
    assert!(registry.forms().any(IlFormRegistration::is_persistable));
    assert!(
        registry
            .dialects()
            .any(|dialect| dialect == &AcmeSummary::FORM.dialect())
    );

    let config = AnalysisEngineConfig::default();
    assert!(config.registry().contains(&AcmeSummary::FORM));
}

#[test]
fn an_external_form_cannot_claim_the_reserved_namespace() {
    let errors = IlRegistryBuilder::standard()
        .with_dialect(DialectId::from_static("fugue.acme"))
        .build()
        .expect_err("the fugue namespace is reserved");

    assert!(matches!(
        errors.errors(),
        [IlRegistryError::ReservedDialect { .. }]
    ));
}

#[test]
fn the_public_typed_query_accepts_an_out_of_tree_form() {
    use std::path::Path;

    use fugue_core::engine::AnalysisEngine;
    use fugue_core::loader::Loader;
    use fugue_core::project::Project;

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ls.elf");
    let loader = Loader::from_file(fixture).expect("the fixture loads");
    let project = Project::new_transient(&loader).expect("the project opens");
    let engine = AnalysisEngine::with_config(project, AnalysisEngineConfig::default())
        .expect("the engine starts");
    engine.analyse().expect("analysis completes");

    let reader = engine.query_reader().expect("a reader is available");
    let function = {
        let project = reader.project().expect("the project is readable");
        project
            .functions()
            .iter()
            .next()
            .expect("the fixture recovers a function")
            .id()
    };

    assert!(
        reader
            .il::<AcmeSummary>(function)
            .expect("an unregistered form queries cleanly")
            .is_none()
    );
    assert!(
        reader
            .il::<CoreECodeIr>(function)
            .expect("a built-in form queries through the same entry point")
            .is_some()
    );
}
