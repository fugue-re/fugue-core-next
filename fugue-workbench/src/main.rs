use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use tracing_subscriber::EnvFilter;
use ts_rs::TS;

use crate::bindings::{
    AddressRequest, CfgResponse, ChangeEvent, FormInfo, FunctionRow, IlResponse, ListingLine,
    MetaResponse, MetricsResponse, MutationResponse, PatchRequest, ProblemRow, RenameRequest,
    SegmentRow, SwitchRow, SymbolRow, XrefRow,
};
use crate::server::AppState;
use crate::session::Session;

mod bindings;
mod error;
mod il_render;
mod server;
mod session;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let matches = Command::new("fugue-workbench")
        .about("Interactive explorer for fugue-core analyses")
        .subcommand(
            Command::new("serve")
                .about("Analyse a binary and serve the workbench UI")
                .arg(
                    Arg::new("input")
                        .value_parser(value_parser!(PathBuf))
                        .help("Binary or persisted project to open; omit to open one from the UI"),
                )
                .arg(
                    Arg::new("address")
                        .long("address")
                        .default_value("127.0.0.1:8080")
                        .help("Socket address to bind"),
                )
                .arg(
                    Arg::new("persist")
                        .long("persist")
                        .action(ArgAction::SetTrue)
                        .help("Open a persistent project rather than a transient analysis"),
                ),
        )
        .subcommand(
            Command::new("export-bindings")
                .about("Write the TypeScript wire types consumed by the frontend")
                .arg(
                    Arg::new("out")
                        .long("out")
                        .default_value("web/src/bindings")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand_required(true)
        .get_matches();

    match matches.subcommand() {
        Some(("serve", arguments)) => serve(arguments),
        Some(("export-bindings", arguments)) => export_bindings(arguments),
        _ => unreachable!("subcommand is required"),
    }
}

fn serve(arguments: &ArgMatches) -> anyhow::Result<()> {
    let address = arguments
        .get_one::<String>("address")
        .expect("address has a default")
        .parse::<SocketAddr>()?;
    let persist = arguments.get_flag("persist");

    let state = AppState::new();
    if let Some(input) = arguments.get_one::<PathBuf>("input") {
        state.set(Session::open(input, persist, state.change_sender())?);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(server::serve(state, address))
}

fn export_bindings(arguments: &ArgMatches) -> anyhow::Result<()> {
    let out = arguments
        .get_one::<PathBuf>("out")
        .expect("out has a default");
    std::fs::create_dir_all(out)?;

    MetaResponse::export_all_to(out)?;
    FormInfo::export_all_to(out)?;
    FunctionRow::export_all_to(out)?;
    SymbolRow::export_all_to(out)?;
    ProblemRow::export_all_to(out)?;
    SwitchRow::export_all_to(out)?;
    SegmentRow::export_all_to(out)?;
    ListingLine::export_all_to(out)?;
    XrefRow::export_all_to(out)?;
    IlResponse::export_all_to(out)?;
    CfgResponse::export_all_to(out)?;
    MetricsResponse::export_all_to(out)?;
    MutationResponse::export_all_to(out)?;
    RenameRequest::export_all_to(out)?;
    AddressRequest::export_all_to(out)?;
    PatchRequest::export_all_to(out)?;
    ChangeEvent::export_all_to(out)?;

    tracing::info!(directory = %out.display(), "wrote TypeScript bindings");
    Ok(())
}
