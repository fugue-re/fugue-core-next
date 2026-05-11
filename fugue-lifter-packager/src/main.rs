use std::process;

use clap::builder::{Arg, ArgAction, Command, ValueHint};
use clap::ArgMatches;
use fugue_lifter_packager::{pack_blob, pack_lifter, sync_languages, unpack_blob, SyncOptions};

#[derive(Debug)]
enum Invocation {
    Pack {
        input_dir: String,
        language: String,
        output_file: String,
        variants: Vec<String>,
    },
    PackBlob {
        input_dir: String,
        language: String,
        output_file: String,
    },
    UnpackBlob {
        input_file: String,
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
            variants,
        } => {
            let variant_refs = variants.iter().map(String::as_str).collect::<Vec<&str>>();
            pack_lifter(input_dir, &language, output_file, &variant_refs)
        }
        Invocation::PackBlob {
            input_dir,
            language,
            output_file,
        } => pack_blob(input_dir, &language, output_file),
        Invocation::UnpackBlob {
            input_file,
            output_file,
        } => unpack_blob(input_file, output_file),
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
        .subcommand(build_pack_blob_command())
        .subcommand(build_unpack_blob_command())
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
        .arg(
            Arg::new("variant")
                .long("variant")
                .help("additional variant to emit alongside the primary; repeatable")
                .action(ArgAction::Append)
                .value_name("name"),
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

fn build_pack_blob_command() -> Command {
    Command::new("pack-blob")
        .about("build a rkyv-serialised dynamic language blob from sleigh sources")
        .arg(
            Arg::new("specs")
                .long("specs")
                .help("language definition directory")
                .action(ArgAction::Set)
                .required(true)
                .value_name("dir")
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
        .arg(
            Arg::new("output")
                .long("output")
                .help("output blob path (gzipped rkyv)")
                .action(ArgAction::Set)
                .required(true)
                .value_name("path")
                .value_hint(ValueHint::FilePath),
        )
}

fn build_unpack_blob_command() -> Command {
    Command::new("unpack-blob")
        .about("decompress a packed blob to its raw rkyv bytes")
        .arg(
            Arg::new("input")
                .long("input")
                .help("packed blob (gzipped rkyv)")
                .action(ArgAction::Set)
                .required(true)
                .value_name("path")
                .value_hint(ValueHint::FilePath),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("output path for raw rkyv bytes")
                .action(ArgAction::Set)
                .required(true)
                .value_name("path")
                .value_hint(ValueHint::FilePath),
        )
}

fn parse_invocation(matches: &ArgMatches) -> Invocation {
    if let Some(("sync", sync_matches)) = matches.subcommand() {
        return Invocation::Sync(parse_sync_options(sync_matches));
    }

    if let Some(("pack-blob", pack_matches)) = matches.subcommand() {
        return Invocation::PackBlob {
            input_dir: pack_matches
                .get_one::<String>("specs")
                .expect("clap guarantees required option")
                .clone(),
            language: pack_matches
                .get_one::<String>("language")
                .expect("clap guarantees required option")
                .clone(),
            output_file: pack_matches
                .get_one::<String>("output")
                .expect("clap guarantees required option")
                .clone(),
        };
    }

    if let Some(("unpack-blob", unpack_matches)) = matches.subcommand() {
        return Invocation::UnpackBlob {
            input_file: unpack_matches
                .get_one::<String>("input")
                .expect("clap guarantees required option")
                .clone(),
            output_file: unpack_matches
                .get_one::<String>("output")
                .expect("clap guarantees required option")
                .clone(),
        };
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
        variants: matches
            .get_many::<String>("variant")
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
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
                variants,
            } if input_dir == "specs"
                && language == "x86:LE:64:default"
                && output_file == "out.gz"
                && variants.is_empty()
        ));
    }

    #[test]
    fn parses_pack_arguments_with_variants() {
        let invocation = parse([
            "lifter-packager",
            "specs",
            "ARM:LE:32:v8",
            "out.gz",
            "--variant",
            "v8T",
        ])
        .unwrap();

        assert!(matches!(
            invocation,
            Invocation::Pack {
                input_dir,
                language,
                output_file,
                variants,
            } if input_dir == "specs"
                && language == "ARM:LE:32:v8"
                && output_file == "out.gz"
                && variants == vec![String::from("v8T")]
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

    #[test]
    fn parses_pack_blob_arguments() {
        let invocation = parse([
            "lifter-packager",
            "pack-blob",
            "--specs",
            "specs",
            "--language",
            "x86:LE:64:default",
            "--output",
            "out.flift",
        ])
        .unwrap();

        assert!(matches!(
            invocation,
            Invocation::PackBlob {
                input_dir,
                language,
                output_file,
            } if input_dir == "specs"
                && language == "x86:LE:64:default"
                && output_file == "out.flift"
        ));
    }

    #[test]
    fn parses_unpack_blob_arguments() {
        let invocation = parse([
            "lifter-packager",
            "unpack-blob",
            "--input",
            "in.flift",
            "--output",
            "out.bin",
        ])
        .unwrap();

        assert!(matches!(
            invocation,
            Invocation::UnpackBlob {
                input_file,
                output_file,
            } if input_file == "in.flift" && output_file == "out.bin"
        ));
    }
}
