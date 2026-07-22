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
    use std::path::{Path, PathBuf};
    use std::process::Command;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_crate = manifest_dir.join("../honk-ebpf");
    let ebpf_common_crate = manifest_dir.join("../honk-ebpf-common");
    let ebpf_target = ebpf_crate.join("target/bpfel-unknown-none/release/honk-ebpf");

    /// aya refuses objects without a `.BTF` section ("no BTF parsed for
    /// object"). Cheap guard: section names live verbatim in the section
    /// header string table, so a byte search for the NUL-terminated name is
    /// sufficient.
    fn object_has_btf(path: &Path) -> bool {
        std::fs::read(path)
            .map(|data| {
                data.windows(5).any(|w| w == b".BTF\0") || data.windows(5).any(|w| w == b".BTF.")
            })
            .unwrap_or(false)
    }

    let candidates = [
        ebpf_target.clone(),
        manifest_dir.join("../../target/honk-core.o"),
    ];

    let obj = candidates.iter().find(|p| p.exists()).cloned();

    let obj = match obj {
        Some(p) if object_has_btf(&p) => {
            println!("cargo:rerun-if-changed={}", p.display());
            p
        }
        _ => {
            // Missing, or stale without .BTF (e.g. built while an environment
            // RUSTFLAGS overrode crates/honk-ebpf/.cargo/config.toml): (re)build.
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
                // An inherited RUSTFLAGS would override the crate's
                // .cargo/config.toml rustflags (--btf, debuginfo) and silently
                // produce a BTF-less object again.
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
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
            if !object_has_btf(&ebpf_target) {
                panic!(
                    "eBPF object at {} has no .BTF section — aya cannot load it. \
                     Rebuild manually:\n  \
                     cd crates/honk-ebpf && cargo +nightly build --release \
                     -Zbuild-std=core --target bpfel-unknown-none",
                    ebpf_target.display()
                );
            }
            println!("cargo:rerun-if-changed={}", ebpf_target.display());
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
