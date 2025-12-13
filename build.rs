fn main() {
    println!("cargo:rerun-if-changed=protos");
    protobuf_codegen::Codegen::new()
        .pure()
        // All inputs and imports from the inputs must reside in `includes` directories.
        .includes(["protos"])
        // Inputs must reside in some of include paths.
        .input("protos/params.proto")
        // Specify output directory relative to Cargo output directory.
        .cargo_out_dir("protos")
        .run_from_script();
    // Only run bindgen if the "fuse" feature is enabled.
    #[cfg(feature = "fuse")]
    {
        // Tell Cargo to re-run this build script if src/fuse_wrappers/all.h changes.
        println!("cargo:rerun-if-changed=src/fuse_wrappers/all.h");

        let fuse3 = pkg_config::probe_library("fuse3")
            .expect("libfuse3 is required to build with feature 'fuse'");

        // The bindgen::Builder is the main entry point
        // to bindgen, and lets you build up options for
        // the resulting bindings.
        let bindings = bindgen::Builder::default()
            // The input header we would like to generate bindings for.
            .header("src/fuse_wrappers/all.h")
            // Add the include paths from pkg-config
            .clang_args(
                fuse3
                    .include_paths
                    .iter()
                    .map(|path| format!("-I{}", path.display())),
            )
            // Tell Cargo to invalidate the built crate whenever any of the
            // included header files changed.
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            // Finish the builder and generate the bindings.
            .generate()
            .expect("Unable to generate bindings for fuse_wrappers/all.h");

        // Write the bindings to the $OUT_DIR/fuse_bindings.rs file.
        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("fuse_bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
