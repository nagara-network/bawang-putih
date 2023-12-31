fn main() {
    // Build variables
    dotenv_build::output(dotenv_build::Config::default()).unwrap();

    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let mut memory_map = std::fs::File::create(out.join("memory.x")).unwrap();
    std::io::Write::write_all(&mut memory_map, include_bytes!("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    // By default, Cargo will re-run a build script whenever
    // any file in the project changes. By specifying `memory.x`
    // here, we ensure the build script is only re-run when
    // `memory.x` is changed.
    println!("cargo:rerun-if-changed=memory.x");
}
