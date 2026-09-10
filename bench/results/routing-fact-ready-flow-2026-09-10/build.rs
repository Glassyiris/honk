use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let baseline = root.join("baseline-codegen.rs").canonicalize().unwrap();
    let candidate = env::var_os("HONK_FACT_EMITTER")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("candidate-codegen.rs"))
        .canonicalize()
        .unwrap();
    let modules = format!(
        "#[path = {baseline:?}] pub mod baseline;\n#[path = {candidate:?}] pub mod candidate;\n"
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("emitters.rs"),
        modules,
    )
    .unwrap();
    println!("cargo:rustc-env=HONK_CODEGEN_PATH={}", candidate.display());
    println!("cargo:rerun-if-changed={}", baseline.display());
    println!("cargo:rerun-if-changed={}", candidate.display());
    println!("cargo:rerun-if-env-changed=HONK_FACT_EMITTER");
}
