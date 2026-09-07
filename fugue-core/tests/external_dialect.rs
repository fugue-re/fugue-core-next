use std::mem::size_of;
use std::path::Path;

use fugue_core::analysis::AnalysisError;
use fugue_core::engine::{AnalyserProvider, AnalysisContext, AnalysisEngine, AnalysisEngineConfig};
use fugue_core::extension::submit;
use fugue_core::il::common::{
    ControlFlowIl, DialectId, IlAnalyser, IlAnalysis, IlArtefact, IlBlockArgId, IlBlockId,
    IlBlockProperties, IlDominance, IlEdgeKinds, IlError, IlGenerationContext, IlGenerationError,
    IlGraph, IlGraphBuilder, IlIndexRange, IlMetadata, IlOpId, IlParentSpan, IlProducer, IlRewrite,
    IlSchemaVersion, IlSourceSpan, IlSsaDef, IlTransformer, IlValueId, PersistableIl, RegisterId,
    SsaIl, SsaVerifier, SsaVerifyError,
};
use fugue_core::il::ecode::{
    ECodeBuilder, ECodeDomain, ECodeIr, ECodeLiveness, ECodeOpSpec, ECodeOpcode,
};
use fugue_core::il::mcode::{
    MCodeBuilder, MCodeOpSpec, MCodeOpcode, MCodeUses, MCodeVar, MCodeVersion,
};
use fugue_core::il::pcode::{
    PCodeBuilder, PCodeIr, PCodeLifterSpaceHandle, PCodeLocation, PCodeLocationProperties,
    PCodeOpSpec, PCodeOpcode,
};
use fugue_core::il::registry::{
    IlDialectRegistration, IlFormRegistration, IlRegistryBuilder, IlRegistryError,
};
use fugue_core::ir::{
    Address, FunctionId, SymbolEntry, SymbolIndex, SymbolProperties, SymbolTableSelector,
};
use fugue_core::loader::Loader;
use fugue_core::project::{ChangeKinds, Project, ProjectError};
use fugue_core::queries::{QueryError, QueryableIl};
use fugue_core::storage::AddressSpaceId;
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

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AcmePersistedSummary {
    metadata: IlMetadata,
    value: u64,
}

impl EstimateSize for AcmePersistedSummary {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl IlArtefact for AcmePersistedSummary {
    const FORM_IDENTIFIER: &str = "acme.summary.persisted";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

impl PersistableIl for AcmePersistedSummary {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(1);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }
}

impl QueryableIl for AcmePersistedSummary {}

submit! { IlFormRegistration::persistable::<AcmePersistedSummary>() }

fugue_core::il::common::il_id!(AcmeValueId, "Acme value");

#[derive(Debug, Copy, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AcmeCfgOp {
    result: AcmeValueId,
}

#[derive(Debug, Copy, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AcmeCfgValue {
    width: u32,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct AcmeCfg {
    metadata: IlMetadata,
    graph: IlGraph,
    operations: Vec<AcmeCfgOp>,
    values: Vec<AcmeCfgValue>,
    edge_args: Vec<IlIndexRange>,
    source_spans: Vec<IlSourceSpan>,
    parent_spans: Vec<IlParentSpan>,
}

impl EstimateSize for AcmeCfg {
    fn estimate_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.graph.estimate_size())
            .saturating_add(
                self.operations
                    .capacity()
                    .saturating_mul(size_of::<AcmeCfgOp>()),
            )
            .saturating_add(
                self.values
                    .capacity()
                    .saturating_mul(size_of::<AcmeCfgValue>()),
            )
            .saturating_add(
                self.edge_args
                    .capacity()
                    .saturating_mul(size_of::<IlIndexRange>()),
            )
            .saturating_add(
                self.source_spans
                    .capacity()
                    .saturating_mul(size_of::<IlSourceSpan>()),
            )
            .saturating_add(
                self.parent_spans
                    .capacity()
                    .saturating_mul(size_of::<IlParentSpan>()),
            )
    }
}

impl IlArtefact for AcmeCfg {
    const FORM_IDENTIFIER: &str = "acme.cfg.graph";

    fn metadata(&self) -> &IlMetadata {
        &self.metadata
    }
}

impl ControlFlowIl for AcmeCfg {
    fn graph(&self) -> &IlGraph {
        &self.graph
    }
}

impl SsaIl for AcmeCfg {
    fn value_count(&self) -> usize {
        self.values.len()
    }

    fn value_definition(&self, value: IlValueId) -> Option<IlSsaDef> {
        self.values.get(value.index())?;
        let operation = IlOpId::try_from_index(value.index()).ok()?;
        self.operations
            .get(operation.index())
            .map(|_| IlSsaDef::Op(operation))
    }

    fn value_width(&self, value: IlValueId) -> Option<u32> {
        self.values.get(value.index()).map(|value| value.width)
    }

    fn block_arg_count(&self) -> usize {
        0
    }

    fn block_arg_block(&self, _arg: IlBlockArgId) -> Option<IlBlockId> {
        None
    }

    fn block_arg_value(&self, _arg: IlBlockArgId) -> Option<IlValueId> {
        None
    }

    fn block_arg_width(&self, _arg: IlBlockArgId) -> Option<u32> {
        None
    }

    fn op_count(&self) -> usize {
        self.operations.len()
    }

    fn op_operands(&self, operation: IlOpId) -> Option<&[IlValueId]> {
        self.operations.get(operation.index()).map(|_| &[][..])
    }

    fn edge_args(&self) -> &[IlIndexRange] {
        &self.edge_args
    }

    fn edge_arg_values(&self) -> &[IlValueId] {
        &[]
    }

    fn memory_domain_count(&self) -> usize {
        0
    }

    fn memory_domain_space(&self, _index: usize) -> Option<AddressSpaceId> {
        None
    }
}

impl PersistableIl for AcmeCfg {
    const SCHEMA: IlSchemaVersion = IlSchemaVersion::new(1);

    fn metadata_mut(&mut self) -> &mut IlMetadata {
        &mut self.metadata
    }
}

impl QueryableIl for AcmeCfg {}

submit! { IlDialectRegistration::new("acme.cfg") }
submit! { IlFormRegistration::persistable::<AcmeCfg>() }

fn acme_cfg() -> AcmeCfg {
    let mut graph = IlGraphBuilder::new();
    let entry = graph
        .push_block_with_source(
            IlIndexRange::new(0, 1).expect("the operation range is valid"),
            IlBlockProperties::ENTRY,
            Address::new(AddressSpaceId::new(0), 0x1000u64),
        )
        .expect("the entry block is allocated");
    let left = graph
        .push_block_with_source(
            IlIndexRange::new(1, 2).expect("the operation range is valid"),
            IlBlockProperties::empty(),
            Address::new(AddressSpaceId::new(0), 0x1004u64),
        )
        .expect("the left block is allocated");
    let right = graph
        .push_block_with_source(
            IlIndexRange::new(2, 3).expect("the operation range is valid"),
            IlBlockProperties::empty(),
            Address::new(AddressSpaceId::new(0), 0x1008u64),
        )
        .expect("the right block is allocated");
    let exit = graph
        .push_block_with_source(
            IlIndexRange::new(3, 4).expect("the operation range is valid"),
            IlBlockProperties::EXIT,
            Address::new(AddressSpaceId::new(0), 0x100cu64),
        )
        .expect("the exit block is allocated");
    graph
        .add_successor(entry, left, IlEdgeKinds::TAKEN)
        .expect("the taken edge is valid");
    graph
        .add_successor(entry, right, IlEdgeKinds::FALL_THROUGH)
        .expect("the fall-through edge is valid");
    graph
        .add_successor(left, exit, IlEdgeKinds::UNCONDITIONAL)
        .expect("the left join edge is valid");
    graph
        .add_successor(right, exit, IlEdgeKinds::UNCONDITIONAL)
        .expect("the right join edge is valid");

    let operations = (0..4)
        .map(|index| AcmeCfgOp {
            result: AcmeValueId::try_from_index(index).expect("the value id is representable"),
        })
        .collect::<Vec<_>>();
    let values = vec![AcmeCfgValue { width: 64 }; 4];
    let source_spans = (0..4)
        .map(|index| {
            IlSourceSpan::try_new(
                IlIndexRange::new(index, index + 1).expect("the span range is valid"),
                Address::new(AddressSpaceId::new(0), 0x1000u64 + index as u64 * 4),
                0,
                1,
            )
            .expect("the source span is valid")
        })
        .collect::<Vec<_>>();
    let parent_spans = (0..4)
        .map(|index| {
            let range = IlIndexRange::new(index, index + 1).expect("the span range is valid");
            IlParentSpan::new(range, range)
        })
        .collect();

    let graph = graph.build(operations.len()).expect("the graph is valid");
    let edge_args = vec![IlIndexRange::EMPTY; graph.successors().len()];
    AcmeCfg {
        metadata: IlMetadata::new(FunctionId::default(), 0u64),
        graph,
        operations,
        values,
        edge_args,
        source_spans,
        parent_spans,
    }
}

#[test]
fn an_external_ssa_dialect_uses_the_common_verifier_contract() {
    let ir = acme_cfg();
    let verifier = SsaVerifier::new(&ir);

    verifier.verify_memory_domains().unwrap();
    verifier.verify_edge_args().unwrap();
    verifier
        .verify_uses::<SsaVerifyError>(|_, _| Ok(()))
        .unwrap();
}

#[test]
fn an_external_control_flow_dialect_builds_analyses_and_persists() {
    let cfg = acme_cfg();
    let entry = cfg.graph.entry_block().expect("the graph has an entry");
    let left = cfg.graph.successors_for(entry)[0];
    let right = cfg.graph.successors_for(entry)[1];
    let exit = cfg.graph.successors_for(left)[0];
    let dominance = cfg.analyse::<IlDominance>();
    let frontiers = dominance.frontiers(cfg.graph.blocks(), cfg.graph.successors());
    let placement = frontiers
        .place_phis(cfg.graph.blocks().len(), [left, right])
        .expect("the definitions name valid blocks");

    assert_eq!(placement.blocks(), &[exit]);
    assert_eq!(cfg.operations[0].result.index(), 0);
    assert_eq!(cfg.values[0].width, 64);
    assert_eq!(cfg.graph.block_sources().len(), 4);
    assert_eq!(
        IlSourceSpan::find(&cfg.source_spans, 2)
            .expect("the operation has provenance")
            .address(),
        Address::new(AddressSpaceId::new(0), 0x1008u64)
    );

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ls.elf");
    let loader = Loader::from_file(fixture).expect("the fixture loads");
    let mut project = Project::new_transient(&loader).expect("the project opens");
    let function = cfg.metadata.function();
    let mut transaction = project.transaction("external control-flow dialect round trip");
    transaction
        .replace_lifted(cfg)
        .expect("the external CFG is serialisable");
    transaction.commit().expect("the external CFG commits");

    let engine = AnalysisEngine::new(project).expect("the engine starts");
    let stored = engine
        .query_reader()
        .expect("a reader is available")
        .lifted::<AcmeCfg>(function)
        .expect("the external CFG is readable")
        .expect("the external CFG survived persistence");

    assert_eq!(stored.graph.blocks().len(), 4);
    assert_eq!(stored.operations.len(), 4);
    assert_eq!(stored.parent_spans.len(), 4);
}

#[test]
fn built_in_dialects_have_target_native_external_build_apis() {
    let metadata = IlMetadata::new(FunctionId::default(), 0u64);

    let mut pcode = PCodeBuilder::new(metadata, IlGraph::default());
    {
        let mut emitter = pcode.emitter();
        let input = emitter
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(0),
                7,
                8,
                PCodeLocationProperties::CONSTANT,
            ))
            .expect("the constant location is allocated");
        let output = emitter
            .intern_location(PCodeLocation::new(
                PCodeLifterSpaceHandle::new(1),
                0,
                8,
                PCodeLocationProperties::UNIQUE,
            ))
            .expect("the output location is allocated");
        emitter
            .emit(PCodeOpSpec::new(PCodeOpcode::Copy), Some(output), [input])
            .expect("the PCode operation is emitted");
        let target = emitter
            .emit_target(Address::new(AddressSpaceId::new(0), 0x1010u64).into())
            .expect("the PCode branch target is allocated");
        emitter
            .emit(
                PCodeOpSpec::new(PCodeOpcode::Branch).with_target(target),
                None,
                [input],
            )
            .expect("the PCode branch is emitted");
    }
    let pcode = pcode.build().expect("the PCode is valid");
    assert_eq!(pcode.ops().len(), 2);
    assert_eq!(pcode.targets().len(), 1);
    assert!(pcode.display().to_string().contains("copy"));

    let mut ecode = ECodeBuilder::new(metadata, IlGraph::default());
    let register = RegisterId::new(0x10);
    let block = IlBlockId::try_from_index(0).expect("the ECode block identifier is valid");
    let (written, arg) = {
        let mut emitter = ecode.emitter();
        let (_, constant_results) = emitter
            .emit(
                ECodeOpSpec::new(ECodeOpcode::Constant, 64).with_immediate(7),
                [],
                1,
            )
            .expect("the ECode operation is emitted");
        let constant = IlValueId::try_from_index(constant_results.start())
            .expect("the ECode constant result exists");
        let (_, written_results) = emitter
            .emit(
                ECodeOpSpec::new(ECodeOpcode::WriteRegister, 64).with_immediate(register.value()),
                [constant],
                1,
            )
            .expect("the ECode register write is emitted");
        let written = IlValueId::try_from_index(written_results.start())
            .expect("the ECode register result exists");
        emitter
            .set_value_domain(written, ECodeDomain::Register(register))
            .expect("the ECode register domain is assigned");
        let arg = emitter
            .emit_block_arg(block, 64)
            .expect("the ECode block argument is emitted");
        emitter
            .set_value_domain(arg, ECodeDomain::Register(register))
            .expect("the ECode block-argument domain is assigned");
        (written, arg)
    };
    let ecode_operation_count = ecode.emitter().op_count();
    let ecode_operations =
        IlIndexRange::new(0, ecode_operation_count).expect("the ECode operation range is valid");
    let mut ecode_graph = IlGraphBuilder::new();
    ecode_graph
        .push_block(
            ecode_operations,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )
        .expect("the ECode block is allocated");
    ecode.set_graph(
        ecode_graph
            .build(ecode_operation_count)
            .expect("the ECode graph is valid"),
    );
    ecode.set_source_spans(vec![
        IlSourceSpan::try_new(
            ecode_operations,
            Address::new(AddressSpaceId::new(0), 0x1000u64),
            0,
            1,
        )
        .expect("the ECode source span is valid"),
    ]);
    ecode.set_parent_spans(vec![IlParentSpan::new(ecode_operations, ecode_operations)]);
    let ecode = ecode.build().expect("the ECode is valid");
    assert_eq!(ecode.ops().len(), 2);
    assert_eq!(ecode.graph().blocks().len(), 1);
    assert_eq!(ecode.block_args().len(), 1);
    assert_eq!(ecode.block_args()[0].value(), arg);
    assert_eq!(
        ecode.value_domain(written),
        Some(ECodeDomain::Register(register))
    );
    assert_eq!(
        ecode.value_domain(arg),
        Some(ECodeDomain::Register(register))
    );
    assert_eq!(ecode.source_spans().len(), 1);
    assert_eq!(ecode.parent_spans().len(), 1);
    assert!(ecode.display().to_string().contains("const"));
    let _: ECodeLiveness = ecode.analyse();

    let mut mcode = MCodeBuilder::new(metadata, IlGraph::default());
    let (bound, variable, aliased) = {
        let mut emitter = mcode.emitter();
        let variable = emitter
            .intern_variable(MCodeVar::register(register, 0))
            .expect("the MCode register variable is interned");
        let aliased = emitter
            .intern_variable(MCodeVar::stack(-8))
            .expect("the MCode stack variable is interned");
        let (_, constant_results) = emitter
            .emit(
                MCodeOpSpec::new(MCodeOpcode::Constant, 64).with_immediate(7),
                [],
                [64],
            )
            .expect("the MCode operation is emitted");
        let constant = IlValueId::try_from_index(constant_results.start())
            .expect("the MCode constant result exists");
        let (_, bound_results) = emitter
            .emit(
                MCodeOpSpec::new(MCodeOpcode::SetVar, 64).with_variable(variable),
                [constant],
                [64],
            )
            .expect("the MCode variable definition is emitted");
        let bound = IlValueId::try_from_index(bound_results.start())
            .expect("the MCode variable result exists");
        emitter
            .bind_value(bound, variable, MCodeVersion::new(1))
            .expect("the MCode variable result is bound");
        (bound, variable, aliased)
    };
    mcode.set_aliased_variables(vec![aliased]);
    let mcode_operation_count = mcode.emitter().op_count();
    let mcode_operations =
        IlIndexRange::new(0, mcode_operation_count).expect("the MCode operation range is valid");
    let mut mcode_graph = IlGraphBuilder::new();
    mcode_graph
        .push_block(
            mcode_operations,
            IlBlockProperties::ENTRY | IlBlockProperties::EXIT,
        )
        .expect("the MCode block is allocated");
    mcode.set_graph(
        mcode_graph
            .build(mcode_operation_count)
            .expect("the MCode graph is valid"),
    );
    mcode.set_source_spans(vec![
        IlSourceSpan::try_new(
            mcode_operations,
            Address::new(AddressSpaceId::new(0), 0x1000u64),
            0,
            1,
        )
        .expect("the MCode source span is valid"),
    ]);
    mcode.set_parent_spans(vec![IlParentSpan::new(mcode_operations, mcode_operations)]);
    let mcode = mcode.build().expect("the MCode is valid");
    assert_eq!(mcode.ops().len(), 2);
    assert_eq!(mcode.graph().blocks().len(), 1);
    assert_eq!(
        mcode
            .binding(bound)
            .expect("the MCode binding is retained")
            .variable(),
        variable
    );
    assert!(mcode.is_aliased(aliased));
    assert_eq!(mcode.source_spans().len(), 1);
    assert_eq!(mcode.parent_spans().len(), 1);
    assert!(mcode.display().to_string().contains("const"));
    assert!(mcode.analyse::<MCodeUses>().uses_for(bound).is_empty());
}

#[derive(Default)]
struct AcmeIlAnalyser {
    next_symbol: usize,
}

impl IlAnalyser for AcmeIlAnalyser {
    const NAME: &'static str = "acme-il-analyser";
    type Input = PCodeIr;

    fn build(_project: &Project) -> Result<Self, AnalysisError> {
        Ok(Self::default())
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
        context: &mut AnalysisContext<'_, '_>,
        _function: FunctionId,
        input: &Self::Input,
    ) -> Result<(), AnalysisError> {
        let project = &context.project;
        let function = input.metadata().function();
        let Some(function) = project.functions().get_by_id(function) else {
            return Ok(());
        };

        context.updates.add_symbol(
            SymbolIndex::new(SymbolTableSelector::new(250), self.next_symbol),
            SymbolEntry::new(
                function.entry(),
                "acme_il_analyser",
                SymbolProperties::LOCAL,
            ),
        );
        self.next_symbol += 1;
        Ok(())
    }

    fn produces(&self) -> ChangeKinds {
        ChangeKinds::SYMBOLS
    }
}

submit! {
    AnalyserProvider::for_il::<AcmeIlAnalyser>()
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
fn an_external_persistable_form_uses_generic_replacement_and_removal() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ls.elf");
    let loader = Loader::from_file(fixture).expect("the fixture loads");
    let mut project = Project::new_transient(&loader).expect("the project opens");
    let function = FunctionId::default();

    {
        let mut transaction = project.transaction("external dialect replacement");
        transaction
            .replace_lifted(AcmePersistedSummary {
                metadata: IlMetadata::new(function, 0u64),
                value: 7,
            })
            .expect("generic replacement succeeds");
        transaction.commit().expect("replacement commits");
    }
    {
        let mut transaction = project.transaction("external dialect removal");
        assert!(
            transaction
                .remove_lifted::<AcmePersistedSummary>(function)
                .expect("typed removal succeeds")
        );
        transaction.commit().expect("removal commits");
    }
    {
        let mut transaction = project.transaction("external dialect replacement");
        transaction
            .replace_lifted(AcmePersistedSummary {
                metadata: IlMetadata::new(function, 0u64),
                value: 11,
            })
            .expect("generic replacement succeeds");
        transaction.commit().expect("replacement commits");
    }

    let engine = AnalysisEngine::new(project).expect("the engine starts");
    let stored = engine
        .query_reader()
        .expect("a reader is available")
        .lifted::<AcmePersistedSummary>(function)
        .expect("the external form is readable")
        .expect("the external form is present");
    assert_eq!(stored.value, 11);
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
        reader.lifted::<AcmeSummary>(function),
        Err(QueryError::Project(ProjectError::Il(
            IlError::MissingRecipe { form }
        ))) if form == AcmeSummary::FORM
    ));
    assert!(
        reader
            .lifted::<ECodeIr>(function)
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
struct AcmeBlockCountTransformer;

impl IlTransformer for AcmeBlockCountTransformer {
    type Input = ECodeIr;
    type Output = AcmeBlockCount;

    fn transform(
        &mut self,
        source: &Self::Input,
        _context: &IlGenerationContext<'_>,
    ) -> Result<Self::Output, IlGenerationError> {
        Ok(AcmeBlockCount {
            metadata: *source.metadata(),
            blocks: source.graph().blocks().len(),
        })
    }
}

impl QueryableIl for AcmeBlockCount {}

submit! { IlFormRegistration::derived::<AcmeBlockCountTransformer>() }

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
struct ConfiguredBlockCountTransformer {
    generated: usize,
}

impl IlTransformer for ConfiguredBlockCountTransformer {
    type Input = ECodeIr;
    type Output = ConfiguredBlockCount;

    fn transform(
        &mut self,
        source: &Self::Input,
        _context: &IlGenerationContext<'_>,
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
        .lifted::<AcmeBlockCount>(function)
        .expect("the external form generates")
        .expect("the engine produced it through the registered transformation");

    assert_eq!(summary.metadata().function(), function);
    assert!(summary.blocks > 0);

    let ssa = reader
        .lifted::<ECodeIr>(function)
        .expect("the source form is available")
        .expect("the transformation source was generated too");
    assert_eq!(summary.blocks, ssa.graph().blocks().len());
}

#[test]
fn the_engine_uses_a_form_registered_only_in_its_configured_registry() {
    let registry = IlRegistryBuilder::standard()
        .with_transformed_form::<ConfiguredBlockCountTransformer>()
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
        .lifted::<ConfiguredBlockCount>(functions[0])
        .expect("the configured form generates")
        .expect("the configured recipe produced its form");
    let second = reader
        .lifted::<ConfiguredBlockCount>(functions[1])
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
        .lifted::<ConfiguredFunctionSummary>(functions[0])
        .expect("the configured root form generates")
        .expect("the configured producer produced its form");
    let second = reader
        .lifted::<ConfiguredFunctionSummary>(functions[1])
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
        reader.lifted::<AcmeBlockCount>(function),
        Err(QueryError::Project(ProjectError::Il(
            IlError::UnregisteredForm { form }
        ))) if form == AcmeBlockCount::FORM
    ));
}
