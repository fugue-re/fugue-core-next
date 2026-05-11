use std::env;
use std::path::PathBuf;

pub(crate) fn out_or_temp_dir() -> PathBuf {
    if let Ok(out_dir) = env::var("OUT_DIR") {
        PathBuf::from(out_dir)
    } else {
        env::temp_dir()
    }
}

pub(crate) fn patched_root_dir(language_def: &str) -> PathBuf {
    let mut sanitised = String::with_capacity(language_def.len());
    for ch in language_def.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitised.push(ch);
        } else {
            sanitised.push('_');
        }
    }
    out_or_temp_dir().join(format!("patched-processors-{sanitised}"))
}
