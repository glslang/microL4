// Links the kernel with its own linker script, which places it at
// KERNEL_VIRT_BASE in the top 2 GiB of the address space.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bin=kernel=-T{dir}/linker.ld");
    println!("cargo:rustc-link-arg-bin=kernel=-zmax-page-size=0x1000");
    println!("cargo:rerun-if-changed=linker.ld");
}
