use std::mem::size_of;
use std::path::Path;

use fugue_core::analysis::AnalysisError;
use fugue_core::analysis::control::CancellationToken;
use fugue_core::engine::change::ChangeKinds;
use fugue_core::engine::{
    Analyser, AnalyserProvider, AnalysisContext, AnalysisEngine, AnalysisEngineConfig,
    IlAnalyserAdapter, ProjectUpdate, ProjectView,
};
use fugue_core::extension::submit;
use fugue_core::il::common::{
    DialectId, IlAnalyser, IlAnalysis, IlArtefact, IlConverter, IlError, IlGenerationContext,
    IlGenerationError, IlMetadata, IlProducer, IlRewrite,
};
use fugue_core::il::ecode::ECodeIr as CoreECodeIr;
use fugue_core::il::ecode::ssa::ECodeSsaIr;
use fugue_core::il::pcode::PCodeIr;
use fugue_core::il::registry::{
    IlDialectRegistration, IlFormRegistration, IlRegistryBuilder, IlRegistryError,
};
use fugue_core::ir::{FunctionId, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector};
use fugue_core::loader::Loader;
use fugue_core::project::{Project, ProjectError};
use fugue_core::queries::{QueryError, QueryableIl};
use fugue_core::types::EstimateSize;

const ACME_IL_ANALYSER_ATTRIBUTE: &str = "acme.il-analyser";

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

#[derive(Default)]
struct AcmeIlAnalyser {
    next_symbol: usize,
}

impl AcmeIlAnalyser {
    fn build(_project: &Project) -> Result<Box<dyn Analyser>, AnalysisError> {
        Ok(Box::new(IlAnalyserAdapter::new(Self::default())))
    }
}

impl IlAnalyser for AcmeIlAnalyser {
    type Input = PCodeIr;

    fn name(&self) -> &'static str {
        "acme-il-analyser"
    }

    fn triggers(&self) -> ChangeKinds {
        ChangeKinds::empty()
    }

    fn can_analyse(&self, project: &Project) -> bool {
        project
            .attributes()
            .get_attr::<bool>(ACME_IL_ANALYSER_ATTRIBUTE)
            .unwrap_or(false)
    }

    fn analyse(
        &mut self,
        project: &ProjectView<'_>,
        _function: FunctionId,
        input: &Self::Input,
        _cx: &AnalysisContext,
        updates: &mut Vec<ProjectUpdate>,
    ) -> Result<(), AnalysisError> {
        let function = input.metadata().function();
        let Some(function) = project.functions().get_by_id(function) else {
            return Ok(());
        };

        updates.push(ProjectUpdate::add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(250), self.next_symbol),
            SymbolEntry::new(
                function.entry(),
                "acme_il_analyser",
                SymbolProperties::LOCAL,
            ),
        ));
        self.next_symbol += 1;
        Ok(())
    }

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::SYMBOLS
    }
}

submit! {
    AnalyserProvider::for_il::<PCodeIr>("acme-il-analyser", AcmeIlAnalyser::build)
}

fn analysed_engine(config: AnalysisEngineConfig) -> AnalysisEngine {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ls.elf");
    let loader = Loader::from_file(fixture).expect("the fixture loads");
    let project = Project::new_transient(&loader).expect("the project opens");
    let engine = AnalysisEngine::with_config(project, config).expect("the engine starts");
    engine.analyse().expect("analysis completes");
    engine
}

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
fn an_il_analyser_runs_through_ordinary_engine_registration() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ls.elf");
    let loader = Loader::from_file(fixture).expect("the fixture loads");
    let mut project = Project::new_transient(&loader).expect("the project opens");
    project
        .attributes_mut()
        .set_attr(ACME_IL_ANALYSER_ATTRIBUTE, true);
    let engine = AnalysisEngine::new(project).expect("the engine starts");

    engine.analyse().expect("analysis completes");

    let reader = engine.query_reader().expect("a reader is available");
    let function = reader
        .project()
        .expect("the project is readable")
        .functions()
        .iter()
        .next()
        .expect("the fixture recovers a function")
        .id();
    assert!(
        reader
            .pcode(function)
            .expect("PCode generation succeeds")
            .is_some()
    );
    let symbols = reader
        .symbols()
        .collect::<Result<Vec<_>, _>>()
        .expect("symbols are readable");
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol.symbol().as_str() == "acme_il_analyser")
    );
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
fn a_registered_form_without_a_recipe_is_reported() {
    let engine = analysed_engine(AnalysisEngineConfig::default());

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

    assert!(matches!(
        reader.il::<AcmeSummary>(function),
        Err(QueryError::Project(ProjectError::Il(
            IlError::MissingRecipe { form }
        ))) if form == AcmeSummary::FORM
    ));
    assert!(
        reader
            .il::<CoreECodeIr>(function)
            .expect("a built-in form queries through the same entry point")
            .is_some()
    );
}

#[derive(Debug)]
struct AcmeBlockCount {
    metadata: IlMetadata,
    blocks: usize,
}

impl EstimateSize for AcmeBlockCount {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl IlArtefact for AcmeBlockCount {
    const FORM_IDENTIFIER: &str = "acme.summary.blocks";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

#[derive(Default)]
struct AcmeBlockCountConverter;

impl IlConverter for AcmeBlockCountConverter {
    type Input = ECodeSsaIr;
    type Output = AcmeBlockCount;

    fn convert(
        &mut self,
        source: &Self::Input,
        _context: &IlGenerationContext<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        Ok(AcmeBlockCount {
            metadata: *source.metadata(),
            blocks: source.graph().blocks().len(),
        })
    }
}

impl QueryableIl for AcmeBlockCount {}

submit! { IlFormRegistration::derived::<AcmeBlockCountConverter>() }

#[derive(Debug)]
struct ConfiguredBlockCount {
    metadata: IlMetadata,
    blocks: usize,
    generation: usize,
}

impl EstimateSize for ConfiguredBlockCount {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl IlArtefact for ConfiguredBlockCount {
    const FORM_IDENTIFIER: &str = "acme.summary.configured";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

#[derive(Default)]
struct ConfiguredBlockCountConverter {
    generated: usize,
}

impl IlConverter for ConfiguredBlockCountConverter {
    type Input = ECodeSsaIr;
    type Output = ConfiguredBlockCount;

    fn convert(
        &mut self,
        source: &Self::Input,
        _context: &IlGenerationContext<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        self.generated += 1;
        Ok(ConfiguredBlockCount {
            metadata: *source.metadata(),
            blocks: source.graph().blocks().len(),
            generation: self.generated,
        })
    }
}

impl QueryableIl for ConfiguredBlockCount {}

#[derive(Debug)]
struct ConfiguredFunctionSummary {
    metadata: IlMetadata,
    generation: usize,
}

impl EstimateSize for ConfiguredFunctionSummary {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl IlArtefact for ConfiguredFunctionSummary {
    const FORM_IDENTIFIER: &str = "acme.summary.root";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

#[derive(Default)]
struct ConfiguredFunctionSummaryProducer {
    generated: usize,
}

impl IlProducer for ConfiguredFunctionSummaryProducer {
    type Output = ConfiguredFunctionSummary;

    fn produce(
        &mut self,
        context: &IlGenerationContext<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<Self::Output, IlGenerationError> {
        self.generated += 1;
        Ok(ConfiguredFunctionSummary {
            metadata: IlMetadata::new(context.function(), context.input_revision()),
            generation: self.generated,
        })
    }
}

impl QueryableIl for ConfiguredFunctionSummary {}

#[test]
fn the_engine_generates_an_external_form_through_its_registered_recipe() {
    let engine = analysed_engine(AnalysisEngineConfig::default());

    let reader = engine.query_reader().expect("a reader is available");
    let function = {
        let project = reader.project().expect("the project is readable");
        project
            .functions()
            .iter()
            .find(|function| function.blocks().count() > 1)
            .expect("the fixture recovers a multi-block function")
            .id()
    };

    let summary = reader
        .il::<AcmeBlockCount>(function)
        .expect("the external form generates")
        .expect("the engine produced it through the registered conversion");

    assert_eq!(summary.metadata().function(), function);
    assert!(summary.blocks > 0);

    let ssa = reader
        .il::<ECodeSsaIr>(function)
        .expect("the source form is available")
        .expect("the conversion source was generated too");
    assert_eq!(summary.blocks, ssa.graph().blocks().len());
}

#[test]
fn the_engine_uses_a_form_registered_only_in_its_configured_registry() {
    let registry = IlRegistryBuilder::standard()
        .with_converted_form::<ConfiguredBlockCountConverter>()
        .build()
        .expect("the configured form is valid");
    let engine = analysed_engine(AnalysisEngineConfig::default().with_registry(registry));
    let reader = engine.query_reader().expect("a reader is available");
    let functions = reader
        .project()
        .expect("the project is readable")
        .functions()
        .iter()
        .take(2)
        .map(|function| function.id())
        .collect::<Vec<_>>();
    assert_eq!(functions.len(), 2);

    let first = reader
        .il::<ConfiguredBlockCount>(functions[0])
        .expect("the configured form generates")
        .expect("the configured recipe produced its form");
    let second = reader
        .il::<ConfiguredBlockCount>(functions[1])
        .expect("the configured form generates again")
        .expect("the configured recipe produced its second form");

    assert!(first.blocks > 0);
    assert!(second.blocks > 0);
    assert_eq!(first.generation, 1);
    assert_eq!(second.generation, 2);
}

#[test]
fn the_engine_uses_a_root_producer_from_its_configured_registry() {
    let registry = IlRegistryBuilder::standard()
        .with_produced_form::<ConfiguredFunctionSummaryProducer>()
        .build()
        .expect("the configured form is valid");
    let engine = analysed_engine(AnalysisEngineConfig::default().with_registry(registry));
    let reader = engine.query_reader().expect("a reader is available");
    let functions = reader
        .project()
        .expect("the project is readable")
        .functions()
        .iter()
        .take(2)
        .map(|function| function.id())
        .collect::<Vec<_>>();
    assert_eq!(functions.len(), 2);

    let first = reader
        .il::<ConfiguredFunctionSummary>(functions[0])
        .expect("the configured root form generates")
        .expect("the configured producer produced its form");
    let second = reader
        .il::<ConfiguredFunctionSummary>(functions[1])
        .expect("the configured root form generates again")
        .expect("the configured producer produced its second form");

    assert_eq!(first.metadata().function(), functions[0]);
    assert_eq!(second.metadata().function(), functions[1]);
    assert_eq!(first.generation, 1);
    assert_eq!(second.generation, 2);
}

#[test]
fn inventory_does_not_override_an_engine_registry() {
    let registry = IlRegistryBuilder::built_in()
        .build()
        .expect("the built-in registry is valid");
    let engine = analysed_engine(AnalysisEngineConfig::default().with_registry(registry));
    let reader = engine.query_reader().expect("a reader is available");
    let function = reader
        .project()
        .expect("the project is readable")
        .functions()
        .iter()
        .next()
        .expect("the fixture recovers a function")
        .id();

    assert!(matches!(
        reader.il::<AcmeBlockCount>(function),
        Err(QueryError::Project(ProjectError::Il(
            IlError::UnregisteredForm { form }
        ))) if form == AcmeBlockCount::FORM
    ));
}
