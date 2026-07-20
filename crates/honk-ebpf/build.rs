fn main() {
    // Rebuild when any source file changes
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
