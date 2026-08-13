use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result as AnyResult;
use arc_swap::ArcSwapOption;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Multipart, Path, Query as QueryParams, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use fugue_core::il::common::{IlArtefact, IlBlockId, IlFormId, IlIndexRange, IlSourceSpan};
use fugue_core::il::ecode::ECodeIr;
use fugue_core::il::ecode::ssa::ECodeSsaIr;
use fugue_core::il::mcode::ssa::MCodeSsaIr;
use fugue_core::il::pcode::PCodeIr;
use fugue_core::il::registry::IlRegistry;
use fugue_core::ir::Address;
use fugue_core::lifter::Lifter;
use fugue_core::queries::QueryReader;
use fugue_core::storage::SegmentStorage;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tower_http::trace::TraceLayer;

use crate::bindings::{
    self, AddressRequest, CfgBlock, CfgEdge, CfgResponse, ChangeEvent, DEFAULT_SPACE, FormInfo,
    FunctionRow, IlResponse, ListingLine, MetaResponse, MetricsResponse, MutationResponse,
    PatchRequest, ProblemRow, RenameRequest, SegmentRow, SwitchRow, SymbolRow, XrefRow,
};
use crate::error::WorkbenchError;
use crate::il_render::IlRenderer;
use crate::session::Session;

const MAX_INSTRUCTION_BYTES: usize = 16;
const CHANGE_CHANNEL_CAPACITY: usize = 512;

#[derive(rust_embed::RustEmbed)]
#[folder = "web/dist"]
struct Assets;

#[derive(Clone)]
pub struct AppState {
    session: Arc<ArcSwapOption<Session>>,
    changes: broadcast::Sender<ChangeEvent>,
}

impl AppState {
    pub fn new() -> Self {
        let (changes, _) = broadcast::channel(CHANGE_CHANNEL_CAPACITY);
        Self {
            session: Arc::new(ArcSwapOption::empty()),
            changes,
        }
    }

    pub fn change_sender(&self) -> broadcast::Sender<ChangeEvent> {
        self.changes.clone()
    }

    pub fn set(&self, session: Session) {
        self.session.store(Some(Arc::new(session)));
    }

    fn subscribe(&self) -> broadcast::Receiver<ChangeEvent> {
        self.changes.subscribe()
    }

    fn current(&self) -> Result<Arc<Session>, WorkbenchError> {
        self.session.load_full().ok_or(WorkbenchError::NoProject)
    }
}

struct CurrentSession(Arc<Session>);

impl std::ops::Deref for CurrentSession {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.0
    }
}

impl FromRequestParts<AppState> for CurrentSession {
    type Rejection = WorkbenchError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, WorkbenchError> {
        state.current().map(CurrentSession)
    }
}

fn renderable_form(form: &IlFormId) -> bool {
    *form == <PCodeIr as IlArtefact>::FORM
        || *form == <ECodeIr as IlArtefact>::FORM
        || *form == <ECodeSsaIr as IlArtefact>::FORM
        || *form == <MCodeSsaIr as IlArtefact>::FORM
}

struct Snapshot<'a> {
    reader: &'a QueryReader,
}

impl<'a> Snapshot<'a> {
    fn new(reader: &'a QueryReader) -> Self {
        Self { reader }
    }

    fn meta(&self) -> Result<MetaResponse, WorkbenchError> {
        let project = self.reader.project()?;
        Ok(MetaResponse {
            arch: project.arch().to_string(),
            language: project.language().id().to_owned(),
            entry_point: project.entry_point().map(bindings::Address::from),
            revision: project.revision().value(),
            default_space: DEFAULT_SPACE.index() as u32,
        })
    }

    fn functions(&self) -> Result<Vec<FunctionRow>, WorkbenchError> {
        let mut names = HashMap::new();
        for entry in self.reader.symbols() {
            let entry = entry?;
            names
                .entry(entry.address())
                .or_insert_with(|| entry.symbol().to_string());
        }

        let project = self.reader.project()?;
        let mut rows = project
            .functions()
            .iter()
            .map(|function| {
                let mut row = FunctionRow::from_function(&function);
                if row.name.is_none() {
                    row.name = names.get(&function.entry()).cloned();
                }
                (function.entry().offset(), row)
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|(offset, _)| *offset);
        Ok(rows.into_iter().map(|(_, row)| row).collect())
    }

    fn symbols(&self) -> Result<Vec<SymbolRow>, WorkbenchError> {
        let mut rows = Vec::new();
        for entry in self.reader.symbols() {
            rows.push(SymbolRow::from_entity(&entry?));
        }
        Ok(rows)
    }

    fn problems(&self) -> Result<Vec<ProblemRow>, WorkbenchError> {
        let mut rows = Vec::new();
        for entry in self.reader.problems() {
            rows.push(ProblemRow::from_entity(&entry?));
        }
        Ok(rows)
    }

    fn switches(&self) -> Result<Vec<SwitchRow>, WorkbenchError> {
        let mut rows = Vec::new();
        for entry in self.reader.switches() {
            rows.push(SwitchRow::from_entity(&entry?));
        }
        Ok(rows)
    }

    fn segments(&self) -> Result<Vec<SegmentRow>, WorkbenchError> {
        let mut rows = Vec::new();
        for entry in self.reader.mappings(DEFAULT_SPACE) {
            rows.push(SegmentRow::from_mapping(&entry?));
        }
        Ok(rows)
    }

    fn xrefs_to(&self, target: Address) -> Result<Vec<XrefRow>, WorkbenchError> {
        let mut rows = Vec::new();
        for reference in self.reader.incoming_references(target) {
            if let Some(row) = XrefRow::from_reference(&reference?) {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    fn xrefs_from(&self, source: Address) -> Result<Vec<XrefRow>, WorkbenchError> {
        let mut rows = Vec::new();
        for reference in self.reader.outgoing_references(source) {
            if let Some(row) = XrefRow::from_reference(&reference?) {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    fn listing(&self, entry: Address) -> Result<Vec<ListingLine>, WorkbenchError> {
        let function = self
            .reader
            .function_id_at(entry)?
            .ok_or_else(|| WorkbenchError::no_function(format!("{:#x}", entry.offset())))?;
        let ecode = self
            .reader
            .ecode(function)?
            .ok_or_else(|| WorkbenchError::no_function(format!("{:#x}", entry.offset())))?;

        let project = self.reader.project()?;
        let segments = project.segments();
        let mut lifter = project.lifter();

        let mut addresses = ecode
            .source_spans()
            .iter()
            .map(IlSourceSpan::address)
            .collect::<Vec<_>>();
        addresses.sort_by_key(Address::offset);
        addresses.dedup();

        Ok(addresses
            .into_iter()
            .filter_map(|address| Self::decode_instruction(segments, &mut lifter, address))
            .collect())
    }

    fn il(&self, entry: Address, form: &str) -> Result<IlResponse, WorkbenchError> {
        let form_id = IlFormId::new(form).map_err(|_| WorkbenchError::unrenderable_form(form))?;
        let function = self
            .reader
            .function_id_at(entry)?
            .ok_or_else(|| WorkbenchError::no_function(format!("{:#x}", entry.offset())))?;

        let renderer = IlRenderer::new(self.reader.project()?.arch());

        let lines = if form_id == <PCodeIr as IlArtefact>::FORM {
            match self.reader.pcode(function)? {
                Some(ir) => renderer.pcode(&ir),
                None => Vec::new(),
            }
        } else if form_id == <ECodeIr as IlArtefact>::FORM {
            match self.reader.ecode(function)? {
                Some(ir) => renderer.ecode(&ir),
                None => Vec::new(),
            }
        } else if form_id == <ECodeSsaIr as IlArtefact>::FORM {
            match self.reader.ecode_ssa(function)? {
                Some(ir) => renderer.ssa(&ir),
                None => Vec::new(),
            }
        } else if form_id == <MCodeSsaIr as IlArtefact>::FORM {
            match self.reader.mcode_ssa(function)? {
                Some(ir) => renderer.mcode_ssa(&ir),
                None => Vec::new(),
            }
        } else {
            return Err(WorkbenchError::unrenderable_form(form));
        };

        Ok(IlResponse {
            form: form.to_owned(),
            lines,
        })
    }

    fn cfg(&self, entry: Address) -> Result<CfgResponse, WorkbenchError> {
        let function = self
            .reader
            .function_id_at(entry)?
            .ok_or_else(|| WorkbenchError::no_function(format!("{:#x}", entry.offset())))?;
        let ecode = self
            .reader
            .ecode(function)?
            .ok_or_else(|| WorkbenchError::no_function(format!("{:#x}", entry.offset())))?;

        let project = self.reader.project()?;
        let segments = project.segments();
        let mut lifter = project.lifter();

        let graph = ecode.graph();
        let spans = ecode.source_spans();
        let mut blocks = Vec::with_capacity(graph.blocks().len());
        let mut edges = Vec::new();

        for (index, block) in graph.blocks().iter().enumerate() {
            let id = IlBlockId::try_from_index(index).expect("block index within graph");
            let block_entry = graph.block_source(id).unwrap_or(entry);

            let mut addresses = spans
                .iter()
                .filter(|span| Self::ranges_overlap(span.destination(), block.operations()))
                .map(IlSourceSpan::address)
                .collect::<Vec<_>>();
            addresses.sort_by_key(Address::offset);
            addresses.dedup();

            let lines = addresses
                .into_iter()
                .filter_map(|address| Self::decode_instruction(segments, &mut lifter, address))
                .collect();

            blocks.push(CfgBlock {
                id: index as u32,
                entry: bindings::Address::from(block_entry),
                entry_block: block.is_entry(),
                lines,
            });

            let successors = graph.successors_for(id);
            let kinds = graph.successor_kinds_for(id);
            for (successor, kind) in successors.iter().zip(kinds) {
                edges.push(CfgEdge {
                    from: index as u32,
                    to: successor.index() as u32,
                    taken: kind.is_taken(),
                    fall_through: kind.is_fall_through(),
                    computed: kind.is_computed(),
                });
            }
        }

        Ok(CfgResponse {
            entry: bindings::Address::from(entry),
            blocks,
            edges,
        })
    }

    fn ranges_overlap(left: IlIndexRange, right: IlIndexRange) -> bool {
        left.start() < right.end() && right.start() < left.end()
    }

    fn decode_instruction(
        segments: &SegmentStorage,
        lifter: &mut Lifter,
        address: Address,
    ) -> Option<ListingLine> {
        let mut buffer = [0u8; MAX_INSTRUCTION_BYTES];
        let read = segments.read_bytes(address, &mut buffer).unwrap_or(0);
        if read == 0 {
            return None;
        }

        let bytes = &buffer[..read];
        let mut mnemonic = String::new();
        let mut operands = String::new();
        match lifter.disassemble_parts(address, bytes, &mut mnemonic, &mut operands) {
            Some(size) if size > 0 => Some(ListingLine::decoded(
                address,
                &bytes[..size.min(read)],
                mnemonic,
                operands,
            )),
            _ => Some(ListingLine::undecoded(address, bytes[0])),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListingRequest {
    entry: String,
}

async fn meta(session: CurrentSession) -> Result<Json<MetaResponse>, WorkbenchError> {
    session
        .read(|reader| Snapshot::new(reader).meta())
        .await
        .map(Json)
}

async fn functions(session: CurrentSession) -> Result<Json<Vec<FunctionRow>>, WorkbenchError> {
    session
        .read(|reader| Snapshot::new(reader).functions())
        .await
        .map(Json)
}

async fn symbols(session: CurrentSession) -> Result<Json<Vec<SymbolRow>>, WorkbenchError> {
    session
        .read(|reader| Snapshot::new(reader).symbols())
        .await
        .map(Json)
}

async fn problems(session: CurrentSession) -> Result<Json<Vec<ProblemRow>>, WorkbenchError> {
    session
        .read(|reader| Snapshot::new(reader).problems())
        .await
        .map(Json)
}

async fn switches(session: CurrentSession) -> Result<Json<Vec<SwitchRow>>, WorkbenchError> {
    session
        .read(|reader| Snapshot::new(reader).switches())
        .await
        .map(Json)
}

async fn segments(session: CurrentSession) -> Result<Json<Vec<SegmentRow>>, WorkbenchError> {
    session
        .read(|reader| Snapshot::new(reader).segments())
        .await
        .map(Json)
}

async fn metrics(session: CurrentSession) -> Result<Json<MetricsResponse>, WorkbenchError> {
    session.metrics().await.map(Json)
}

async fn listing(
    session: CurrentSession,
    QueryParams(request): QueryParams<ListingRequest>,
) -> Result<Json<Vec<ListingLine>>, WorkbenchError> {
    let entry = bindings::Address::decode(&request.entry)?;
    session
        .read(move |reader| Snapshot::new(reader).listing(entry))
        .await
        .map(Json)
}

async fn xrefs_to(
    session: CurrentSession,
    Path(address): Path<String>,
) -> Result<Json<Vec<XrefRow>>, WorkbenchError> {
    let target = bindings::Address::decode(&address)?;
    session
        .read(move |reader| Snapshot::new(reader).xrefs_to(target))
        .await
        .map(Json)
}

async fn xrefs_from(
    session: CurrentSession,
    Path(address): Path<String>,
) -> Result<Json<Vec<XrefRow>>, WorkbenchError> {
    let source = bindings::Address::decode(&address)?;
    session
        .read(move |reader| Snapshot::new(reader).xrefs_from(source))
        .await
        .map(Json)
}

async fn forms() -> Json<Vec<FormInfo>> {
    let mut forms = IlRegistry::standard()
        .forms()
        .map(|registration| {
            FormInfo::from_registration(registration, renderable_form(registration.form()))
        })
        .collect::<Vec<_>>();
    forms.sort_by(|left, right| left.id.cmp(&right.id));
    Json(forms)
}

async fn il(
    session: CurrentSession,
    Path((address, form)): Path<(String, String)>,
) -> Result<Json<IlResponse>, WorkbenchError> {
    let entry = bindings::Address::decode(&address)?;
    session
        .read(move |reader| Snapshot::new(reader).il(entry, &form))
        .await
        .map(Json)
}

async fn cfg(
    session: CurrentSession,
    Path(address): Path<String>,
) -> Result<Json<CfgResponse>, WorkbenchError> {
    let entry = bindings::Address::decode(&address)?;
    session
        .read(move |reader| Snapshot::new(reader).cfg(entry))
        .await
        .map(Json)
}

async fn rename(
    session: CurrentSession,
    Json(request): Json<RenameRequest>,
) -> Result<Json<MutationResponse>, WorkbenchError> {
    let address = bindings::Address::decode(&request.address)?;
    let function = session
        .read(move |reader| Ok(reader.function_id_at(address)?.is_some()))
        .await?;
    let revision = session.rename(address, request.name, function).await?;
    Ok(Json(MutationResponse { revision }))
}

async fn define_function(
    session: CurrentSession,
    Json(request): Json<AddressRequest>,
) -> Result<Json<MutationResponse>, WorkbenchError> {
    let address = bindings::Address::decode(&request.address)?;
    let revision = session.define_function(address).await?;
    Ok(Json(MutationResponse { revision }))
}

async fn undefine_function(
    session: CurrentSession,
    Json(request): Json<AddressRequest>,
) -> Result<Json<MutationResponse>, WorkbenchError> {
    let address = bindings::Address::decode(&request.address)?;
    let revision = session.undefine_function(address).await?;
    Ok(Json(MutationResponse { revision }))
}

async fn patch_bytes(
    session: CurrentSession,
    Json(request): Json<PatchRequest>,
) -> Result<Json<MutationResponse>, WorkbenchError> {
    let address = bindings::Address::decode(&request.address)?;
    let hex = request
        .bytes
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if hex.is_empty()
        || hex.len() % 2 != 0
        || !hex.chars().all(|character| character.is_ascii_hexdigit())
    {
        return Err(WorkbenchError::bad_request(
            "byte patch must be an even-length hex string",
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let digits = std::str::from_utf8(pair).expect("hex digits are ascii");
        bytes.push(u8::from_str_radix(digits, 16).expect("validated hex digits"));
    }
    let revision = session.patch_bytes(address, bytes).await.map_err(|error| {
        WorkbenchError::bad_request(format!(
            "{error} — the target must be a writable, mapped region"
        ))
    })?;
    Ok(Json(MutationResponse { revision }))
}

async fn open(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<MetaResponse>, WorkbenchError> {
    let mut data = None::<Vec<u8>>;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| WorkbenchError::bad_request(error.to_string()))?
    {
        if field.name() == Some("file") {
            let bytes = field
                .bytes()
                .await
                .map_err(|error| WorkbenchError::bad_request(error.to_string()))?;
            data = Some(bytes.to_vec());
        }
    }

    let bytes = data.ok_or_else(|| WorkbenchError::bad_request("upload has no file field"))?;
    let sender = state.change_sender();
    let session = tokio::task::spawn_blocking(move || Session::from_bytes(bytes, sender))
        .await
        .map_err(|_| WorkbenchError::TaskCancelled)??;
    state.set(session);

    let meta = state
        .current()?
        .read(|reader| Snapshot::new(reader).meta())
        .await?;
    Ok(Json(meta))
}

async fn changes(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    let receiver = state.subscribe();
    upgrade.on_upgrade(move |socket| stream_changes(socket, receiver))
}

async fn stream_changes(mut socket: WebSocket, mut receiver: broadcast::Receiver<ChangeEvent>) {
    loop {
        match receiver.recv().await {
            Ok(event) => {
                let Ok(payload) = serde_json::to_string(&event) else {
                    continue;
                };
                if socket.send(Message::Text(payload.into())).await.is_err() {
                    break;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => break,
        }
    }
}

async fn assets(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
            content.data.into_owned(),
        )
            .into_response();
    }

    match Assets::get("index.html") {
        Some(content) => (
            [(header::CONTENT_TYPE, "text/html".to_owned())],
            content.data.into_owned(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "frontend assets not built").into_response(),
    }
}

pub async fn serve(state: AppState, address: SocketAddr) -> AnyResult<()> {
    let router = Router::new()
        .route("/api/open", post(open))
        .route("/api/meta", get(meta))
        .route("/api/functions", get(functions))
        .route("/api/symbols", get(symbols))
        .route("/api/problems", get(problems))
        .route("/api/switches", get(switches))
        .route("/api/segments", get(segments))
        .route("/api/metrics", get(metrics))
        .route("/api/forms", get(forms))
        .route("/api/listing", get(listing))
        .route("/api/xrefs/to/{address}", get(xrefs_to))
        .route("/api/xrefs/from/{address}", get(xrefs_from))
        .route("/api/function/{address}/il/{form}", get(il))
        .route("/api/function/{address}/cfg", get(cfg))
        .route("/api/mutate/rename", post(rename))
        .route("/api/mutate/define-function", post(define_function))
        .route("/api/mutate/undefine-function", post(undefine_function))
        .route("/api/mutate/patch", post(patch_bytes))
        .route("/api/changes", get(changes))
        .fallback(assets)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "fugue-workbench listening");
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod test;
