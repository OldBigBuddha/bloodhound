use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const EBPF_MANIFEST: &str = "../bloodhound-ebpf/Cargo.toml";
const EBPF_TARGET: &str = "bpfel-unknown-none";

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let target_dir = out_dir.join("bloodhound-ebpf");

    println!("cargo:rerun-if-changed=../bloodhound-ebpf/src");
    println!("cargo:rerun-if-changed=../bloodhound-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../bloodhound-ebpf/Cargo.lock");
    println!("cargo:rerun-if-changed=../bloodhound-ebpf/.cargo/config.toml");
    println!("cargo:rerun-if-changed=../bloodhound-common/src");

    let host = env::var("HOST").expect("HOST not set");
    let bpf_arch = match host.split_once('-') {
        Some((arch, _)) => arch,
        None => host.as_str(),
    };

    let sep = "\x1f";
    let mut rustflags = OsString::new();
    for s in [
        "--cfg=bpf_target_arch=\"",
        bpf_arch,
        "\"",
        sep,
        "-Cdebuginfo=2",
        sep,
        "-Clink-arg=--btf",
    ] {
        rustflags.push(s);
    }

    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--manifest-path",
        EBPF_MANIFEST,
        "-Z",
        "build-std=core",
        "--bins",
        "--release",
        "--target",
        EBPF_TARGET,
    ])
    .arg("--target-dir")
    .arg(&target_dir)
    .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
    .env_remove("RUSTC")
    .env_remove("RUSTC_WORKSPACE_WRAPPER")
    .stdout(Stdio::null())
    .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .expect("failed to spawn cargo for bloodhound-ebpf");
    if !status.success() {
        panic!("bloodhound-ebpf build failed: {status:?}");
    }
}
