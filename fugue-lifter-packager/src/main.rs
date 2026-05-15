use std::any::Any;
use std::path::PathBuf;
use std::process::exit;

use clap::builder::{Arg, ArgAction, Command, ValueHint};
use clap::ArgMatches;
use fugue_lifter_packager::Packager;

fn main() {
    let cmd = Command::new("lifter-packager")
        .arg_required_else_help(true)
        .subcommand_negates_reqs(true)
        .subcommand(SyncArgs::command())
        .subcommand(UnpackBlobArgs::command());

    #[cfg(feature = "bundled-compiler")]
    let cmd = PackArgs::command(cmd.subcommand(PackBlobArgs::command()));

    let matches = cmd.get_matches();

    if let Err(e) = run(&matches) {
        eprintln!("error: {e}");
        exit(-1);
    }
}

fn run(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let packager = Packager::new();
    match matches.subcommand() {
        Some(("sync", sub)) => {
            let args = SyncArgs::from_matches(sub);
            match args.dir {
                Some(dir) => packager.sync_local(dir)?,
                None => packager.sync_upstream(args.reference)?,
            }
        }
        Some(("unpack-blob", sub)) => {
            let args = UnpackBlobArgs::from_matches(sub);
            packager.unpack_blob(args.input, args.output)?
        }
        #[cfg(feature = "bundled-compiler")]
        Some(("pack-blob", sub)) => {
            let args = PackBlobArgs::from_matches(sub);
            packager.pack_blob(args.specs, &args.language, args.output)?
        }
        #[cfg(feature = "bundled-compiler")]
        _ => {
            let args = PackArgs::from_matches(&matches);
            packager.pack_lifter(
                args.language_specs,
                &args.language,
                args.output_file,
                &args.variants,
            )?
        }
        #[cfg(not(feature = "bundled-compiler"))]
        _ => unreachable!("clap rejects empty invocations when `bundled-compiler` is disabled"),
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

fn required<'a, T>(matches: &'a ArgMatches, name: &str) -> &'a T
where
    T: Any + Clone + Send + Sync + 'static,
{
    matches
        .get_one::<T>(name)
        .expect("clap guarantees required argument")
}

struct SyncArgs<'a> {
    dir: Option<&'a PathBuf>,
    reference: Option<&'a str>,
}

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

struct UnpackBlobArgs<'a> {
    input: &'a PathBuf,
    output: &'a PathBuf,
}

impl<'a> UnpackBlobArgs<'a> {
    fn command() -> Command {
        Command::new("unpack-blob")
            .about("decompress a packed blob to its raw bytes")
            .arg(required_path("input", "packed blob"))
            .arg(required_path("output", "output path for raw bytes"))
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            input: required(matches, "input"),
            output: required(matches, "output"),
        }
    }
}

#[cfg(feature = "bundled-compiler")]
struct PackBlobArgs<'a> {
    specs: &'a PathBuf,
    language: &'a str,
    output: &'a PathBuf,
}

#[cfg(feature = "bundled-compiler")]
impl<'a> PackBlobArgs<'a> {
    fn command() -> Command {
        Command::new("pack-blob")
            .about("build a serialised dynamic language blob from sleigh sources")
            .arg(
                required_path("specs", "language definition directory")
                    .value_hint(ValueHint::DirPath),
            )
            .arg(
                Arg::new("language")
                    .long("language")
                    .help("language identifier (e.g. x86:LE:64:default)")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_name("id"),
            )
            .arg(required_path("output", "output blob path"))
    }

    fn from_matches(matches: &'a ArgMatches) -> Self {
        Self {
            specs: required(matches, "specs"),
            language: required::<String>(matches, "language").as_str(),
            output: required(matches, "output"),
        }
    }
}

#[cfg(feature = "bundled-compiler")]
struct PackArgs<'a> {
    language_specs: &'a PathBuf,
    language: &'a str,
    output_file: &'a PathBuf,
    variants: Vec<&'a str>,
}

#[cfg(feature = "bundled-compiler")]
impl<'a> PackArgs<'a> {
    fn command(cmd: Command) -> Command {
        cmd.arg(
            Arg::new("language-specs")
                .value_name("language-specs")
                .help("language definition directory")
                .required(true)
                .value_hint(ValueHint::DirPath),
        )
        .arg(
            Arg::new("language")
                .value_name("language")
                .help("language identifier")
                .required(true),
        )
        .arg(
            Arg::new("output-file")
                .value_name("output-file")
                .help("compressed lifter output")
                .required(true)
                .value_hint(ValueHint::FilePath),
        )
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
            language_specs: required(matches, "language-specs"),
            language: required::<String>(matches, "language").as_str(),
            output_file: required(matches, "output-file"),
            variants: matches
                .get_many::<String>("variant")
                .map(|values| values.map(String::as_str).collect())
                .unwrap_or_default(),
        }
    }
}
