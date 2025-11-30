use std::env;

fn main() {
    // Skip this build script on Windows
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        return;
    }
    cc::Build::new()
        .file("src/lite/getpath.c")
        .compile("securefs_getpath");
}
