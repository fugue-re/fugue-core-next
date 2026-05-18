use std::any::Any;
use std::error::Error;
use std::path::PathBuf;
use std::process::exit;

use clap::builder::{Arg, ArgAction, Command, ValueHint};
use clap::ArgMatches;
use fugue_lifter_packager::Packager;

fn main() {
    let cmd = Command::new("lifter-packager")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand(UnpackDynamicArgs::command())
        .subcommand(UnpackStaticArgs::command());

    #[cfg(feature = "sync")]
    let cmd = cmd.subcommand(SyncArgs::command());

    #[cfg(feature = "build")]
    let cmd = cmd
        .subcommand(BuildDynamicArgs::command())
        .subcommand(BuildStaticArgs::command());

    let matches = cmd.get_matches();

    if let Err(e) = run(&matches) {
        eprintln!("error: {e}");
        exit(-1);
    }
}

fn run(matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let packager = Packager::new();
    match matches.subcommand() {
        #[cfg(feature = "sync")]
        Some(("sync", sub)) => {
            let args = SyncArgs::from_matches(sub);
            match args.dir {
                Some(dir) => packager.sync_local(dir)?,
                None => packager.sync_upstream(args.reference)?,
            }
        }
        Some(("unpack-dynamic", sub)) => {
            let args = UnpackDynamicArgs::from_matches(sub);
            packager.unpack_dynamic(args.input, args.output)?
        }
        Some(("unpack-static", sub)) => {
            let args = UnpackStaticArgs::from_matches(sub);
            packager.unpack_static(args.input, args.output)?
        }
        #[cfg(feature = "build")]
        Some(("build-dynamic", sub)) => {
            let args = BuildDynamicArgs::from_matches(sub);
            packager.build_dynamic(args.language_db, args.language, args.output)?
        }
        #[cfg(feature = "build")]
        Some(("build-static", sub)) => {
            let args = BuildStaticArgs::from_matches(sub);
            packager.build_static(
                args.language_db,
                args.language,
                args.output,
                &args.variants,
            )?
        }
        _ => unreachable!("clap rejects unknown or empty invocations"),
    }
    Ok(())
}

fn required_path(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::Set)
        .required(true)
        .value_name("path")
        .value_hint(ValueHint::FilePath)
}

#[cfg(feature = "build")]
fn required_language() -> Arg {
    Arg::new("language")
        .long("language")
        .help("language identifier (e.g. x86:LE:64:default)")
        .action(ArgAction::Set)
        .required(true)
        .value_name("id")
}

fn required<'a, T>(matches: &'a ArgMatches, name: &str) -> &'a T
where
    T: Any + Clone + Send + Sync + 'static,
{
    matches
        .get_one::<T>(name)
        .expect("clap guarantees required argument")
}

#[cfg(feature = "sync")]
struct SyncArgs<'a> {
    dir: Option<&'a PathBuf>,
    reference: Option<&'a str>,
}

#[cfg(feature = "sync")]
impl<'a> SyncArgs<'a> {
    fn command() -> Command {
        Command::new("sync")
            .about("refresh vendored language definitions")
            .arg(
                Arg::new("dir")
                    .long("dir")
                    .help("use an existing local Ghidra checkout")
                    .action(ArgAction::Set)
                    .value_name("path")
                    .value_hint(ValueHint::DirPath)
                    .conflicts_with("ref"),
            )
            .arg(
                Arg::new("ref")
                    .long("ref")
                    .help("sync from a specific upstream ref")
                    .action(ArgAction::Set)
                    .value_name("git-ref")
                    .value_hint(ValueHint::Other)
                    .conflicts_with("dir"),
            )
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            dir: matches.get_one::<PathBuf>("dir"),
            reference: matches.get_one::<String>("ref").map(String::as_str),
        }
    }
}

struct UnpackDynamicArgs<'a> {
    input: &'a PathBuf,
    output: &'a PathBuf,
}

impl<'a> UnpackDynamicArgs<'a> {
    fn command() -> Command {
        Command::new("unpack-dynamic")
            .about("unpack a runtime loadable lifter package")
            .arg(required_path("input", "packed dynamic language"))
            .arg(required_path("output", "output path for raw bytes"))
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            input: required(matches, "input"),
            output: required(matches, "output"),
        }
    }
}

struct UnpackStaticArgs<'a> {
    input: &'a PathBuf,
    output: &'a PathBuf,
}

impl<'a> UnpackStaticArgs<'a> {
    fn command() -> Command {
        Command::new("unpack-static")
            .about("unpack a compilable lifter implementation")
            .arg(required_path("input", "packed lifter source"))
            .arg(required_path("output", "output path for raw source"))
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            input: required(matches, "input"),
            output: required(matches, "output"),
        }
    }
}

#[cfg(feature = "build")]
struct BuildDynamicArgs<'a> {
    language_db: &'a PathBuf,
    language: &'a str,
    output: &'a PathBuf,
}

#[cfg(feature = "build")]
impl<'a> BuildDynamicArgs<'a> {
    fn command() -> Command {
        Command::new("build-dynamic")
            .about("generate a runtime loadable lifter package")
            .arg(
                required_path("language-db", "language definition directory")
                    .value_hint(ValueHint::DirPath),
            )
            .arg(required_language())
            .arg(required_path("output", "output package path"))
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            language_db: required(matches, "language-db"),
            language: required::<String>(matches, "language").as_str(),
            output: required(matches, "output"),
        }
    }
}

#[cfg(feature = "build")]
struct BuildStaticArgs<'a> {
    language_db: &'a PathBuf,
    language: &'a str,
    output: &'a PathBuf,
    variants: Vec<&'a str>,
}

#[cfg(feature = "build")]
impl<'a> BuildStaticArgs<'a> {
    fn command() -> Command {
        Command::new("build-static")
            .about("generate a compilable lifter implementation")
            .arg(
                required_path("language-db", "language definition directory")
                    .value_hint(ValueHint::DirPath),
            )
            .arg(required_language())
            .arg(required_path("output", "output package path"))
            .arg(
                Arg::new("variant")
                    .long("variant")
                    .help("additional variant to emit alongside the primary; repeatable")
                    .action(ArgAction::Append)
                    .value_name("name"),
            )
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            language_db: required(matches, "language-db"),
            language: required::<String>(matches, "language").as_str(),
            output: required(matches, "output"),
            variants: matches
                .get_many::<String>("variant")
                .map(|values| values.map(String::as_str).collect())
                .unwrap_or_default(),
        }
    }
}
