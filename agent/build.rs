use std::env;
use std::path::PathBuf;

fn main() {
    // 1. Tell Cargo to re-run this script if the header changes
    println!("cargo:rerun-if-changed=../driver/include/shared_def.h");

    // 2. Use Bindgen to generate Rust structs from C++
    let bindings = bindgen::Builder::default()
        // The input header
        .header("../driver/include/shared_def.h")
        // Formatting options
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .layout_tests(false)
        .derive_default(true)
        .derive_copy(true)
        .derive_debug(true)
        // Generate the file
        .generate()
        .expect("Unable to generate bindings");

    // 3. Write the bindings to the $OUT_DIR (standard Rust build practice)
    // Or write directly to src/bindings.rs if you prefer visible source
    let out_path = PathBuf::from("src/bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
