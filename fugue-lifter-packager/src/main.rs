use std::{env, process};

use fugue_lifter_packager::pack_lifter;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <language-specs> <language> <output-file>",
            args[0]
        );
        process::exit(1);
    }

    let input_dir = &args[1];
    let language = &args[2];
    let output_file = &args[3];

    if let Err(e) = pack_lifter(input_dir, language, output_file) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
