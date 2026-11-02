// Links root with the user programs' linker script, which places it at
// 0x400000 with a page-aligned segment per permission.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins=-T{dir}/../link.ld");
    println!("cargo:rustc-link-arg-bins=-zmax-page-size=0x1000");
    println!("cargo:rerun-if-changed=../link.ld");
}
