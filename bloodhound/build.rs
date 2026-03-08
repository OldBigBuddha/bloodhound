use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir);

    println!("cargo:rerun-if-changed=../bloodhound-ebpf/src");

    let package = aya_build::Package {
        name: "bloodhound-ebpf",
        root_dir: "../bloodhound-ebpf",
        ..Default::default()
    };

    match aya_build::build_ebpf([package], aya_build::Toolchain::default()) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("WARNING: aya-build copy failed: {}", e);
        }
    }
}
