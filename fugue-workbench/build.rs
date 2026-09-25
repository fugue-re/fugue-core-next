use std::fs;
use std::path::Path;

const PLACEHOLDER: &str = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>fugue · workbench</title></head><body style=\"background:#080a0e;color:#8a94a5;font-family:monospace;display:flex;height:100vh;align-items:center;justify-content:center\">frontend assets not built — run <code style=\"color:#e8b24a;margin:0 6px\">npm run build</code> in fugue-workbench/web</body></html>\n";

fn main() {
    let index = Path::new("web/dist/index.html");
    if !index.exists() {
        fs::create_dir_all("web/dist").expect("create web/dist");
        fs::write(index, PLACEHOLDER).expect("write placeholder index.html");
    }
    println!("cargo:rerun-if-changed=web/dist");
}
