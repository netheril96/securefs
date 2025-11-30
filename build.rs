use std::env;
use std::path::PathBuf;

fn main() {
    // Skip this build script on Windows
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        return;
    }

    // It's good practice to use a wrapper header for bindgen.
    // This tells cargo to re-run the build script if wrapper.h changes.
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        // The wrapper header which includes fcntl.h
        .header("src/fcntl_wrapper.h")
        // Invalidate the built crate whenever any of the included files changed
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings for fcntl.h");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("fcntl_bindings.rs"))
        .expect("Couldn't write bindings!");
}
