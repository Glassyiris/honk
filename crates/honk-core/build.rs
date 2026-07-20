//! Build script for honk-core.
//!
//! When the `ebpf` feature is enabled, this script ensures the eBPF object
//! file is available and copies it into `OUT_DIR` so `lib.rs` can embed it
//! via `include_bytes!`.  If the object does not exist yet, it is built
//! automatically using the nightly toolchain.

fn main() {
    #[cfg(feature = "ebpf")]
    embed_ebpf_object();
}

#[cfg(feature = "ebpf")]
fn embed_ebpf_object() {
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_crate = manifest_dir.join("../honk-ebpf");
    let ebpf_common_crate = manifest_dir.join("../honk-ebpf-common");
    let ebpf_target = ebpf_crate.join("target/bpfel-unknown-none/release/honk-ebpf");

    let candidates = [
        ebpf_target.clone(),
        manifest_dir.join("../../target/honk-core.o"),
    ];

    let obj = candidates.iter().find(|p| p.exists()).cloned();

    let obj = match obj {
        Some(p) => {
            println!("cargo:rerun-if-changed={}", p.display());
            p
        }
        None => {
            println!("cargo:warning=Building eBPF object (one-time, ~30s)...");
            let status = Command::new("cargo")
                .args([
                    "+nightly",
                    "build",
                    "--release",
                    "-Zbuild-std=core",
                    "--target",
                    "bpfel-unknown-none",
                ])
                .current_dir(&ebpf_crate)
                .status()
                .expect("failed to build eBPF object");

            if !status.success() {
                panic!(
                    "eBPF build failed. Build manually:\n  \
                     cd crates/honk-ebpf && cargo +nightly build --release \
                     -Zbuild-std=core --target bpfel-unknown-none"
                );
            }
            ebpf_target
        }
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("honk-ebpf.o");
    std::fs::copy(&obj, &dest)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {}", obj.display(), dest.display(), e));

    println!(
        "cargo:rerun-if-changed={}",
        ebpf_crate.join("src").display()
    );
    // Track all individual eBPF source files for rebuild
    let ebpf_src = ebpf_crate.join("src");
    if ebpf_src.is_dir() {
        for entry in std::fs::read_dir(&ebpf_src).unwrap() {
            let entry = entry.unwrap();
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_common_crate.join("src").display()
    );
    println!("cargo:rustc-env=HONK_EBPF_OBJECT={}", dest.display());
    println!(
        "cargo:warning=eBPF object embedded ({} bytes)",
        obj.metadata().map(|m| m.len()).unwrap_or(0)
    );
}
