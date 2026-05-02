use std::process;

use clap::builder::{Arg, ArgAction, Command, ValueHint};
use clap::ArgMatches;
use fugue_lifter_packager::{pack_lifter, sync_languages, SyncOptions};

#[derive(Debug)]
enum Invocation {
    Pack {
        input_dir: String,
        language: String,
        output_file: String,
    },
    Sync(SyncOptions),
}

fn main() {
    let matches = build_command().get_matches();
    let invocation = parse_invocation(&matches);

    let result = match invocation {
        Invocation::Pack {
            input_dir,
            language,
            output_file,
        } => pack_lifter(input_dir, &language, output_file),
        Invocation::Sync(options) => sync_languages(&options),
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn build_command() -> Command {
    Command::new("lifter-packager")
        .subcommand_required(false)
        .subcommand_negates_reqs(true)
        .arg_required_else_help(true)
        .subcommand(build_sync_command())
        .arg(
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
}

fn build_sync_command() -> Command {
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

fn parse_invocation(matches: &ArgMatches) -> Invocation {
    if let Some(("sync", sync_matches)) = matches.subcommand() {
        return Invocation::Sync(parse_sync_options(sync_matches));
    }

    Invocation::Pack {
        input_dir: matches
            .get_one::<String>("language-specs")
            .expect("clap guarantees required positional")
            .clone(),
        language: matches
            .get_one::<String>("language")
            .expect("clap guarantees required positional")
            .clone(),
        output_file: matches
            .get_one::<String>("output-file")
            .expect("clap guarantees required positional")
            .clone(),
    }
}

fn parse_sync_options(matches: &ArgMatches) -> SyncOptions {
    let mut options = SyncOptions::new();

    if let Some(dir) = matches.get_one::<String>("dir") {
        options = options.with_dir(dir);
    }

    if let Some(reference) = matches.get_one::<String>("ref") {
        options = options.with_reference(reference);
    }

    options
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use clap::error::ErrorKind;

    use super::{build_command, parse_invocation, Invocation};

    fn parse<I, T>(arguments: I) -> Result<Invocation, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = build_command().try_get_matches_from(arguments)?;
        Ok(parse_invocation(&matches))
    }

    #[test]
    fn parses_legacy_pack_arguments() {
        let invocation =
            parse(["lifter-packager", "specs", "x86:LE:64:default", "out.gz"]).unwrap();

        assert!(matches!(
            invocation,
            Invocation::Pack {
                input_dir,
                language,
                output_file,
            } if input_dir == "specs"
                && language == "x86:LE:64:default"
                && output_file == "out.gz"
        ));
    }

    #[test]
    fn parses_sync_arguments() {
        let invocation = parse(["lifter-packager", "sync", "--dir", "/tmp/ghidra"]).unwrap();

        assert!(matches!(
            invocation,
            Invocation::Sync(options)
                if options.dir().map(|path| path.to_string_lossy().into_owned())
                    == Some(String::from("/tmp/ghidra"))
        ));
    }

    #[test]
    fn rejects_missing_sync_argument_value() {
        let error = parse(["lifter-packager", "sync", "--ref"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }
}
