fn main() {
    println!("cargo:rerun-if-changed=src/sock/epoll.c");
    println!("cargo:rerun-if-changed=src/sock/epoll.h");
    println!("cargo:rerun-if-changed=src/sock/ebpf_kern.c");

    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "linux" {
        return;
    }

    println!("cargo:rustc-link-lib=pthread");

    cc::Build::new()
        .file("src/sock/epoll.c")
        .include("src/sock")
        .flag_if_supported("-O3")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .compile("lure_epoll");

    if std::env::var_os("CARGO_FEATURE_EBPF").is_some() {
        build_ebpf_object().expect("failed to build ebpf object");
    }
}

fn build_ebpf_object() -> Result<(), Box<dyn std::error::Error>> {
    use std::{path::PathBuf, process::Command};

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let out_obj = out_dir.join("lure_sockhash_kern.o");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    let arch = match target_arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        other => other,
    };

    let arch_define = format!("-D__TARGET_ARCH_{arch}");
    let status = Command::new("clang")
        .args(["-target", "bpfel"])
        .arg(&arch_define)
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-c",
            "src/sock/ebpf_kern.c",
            "-o",
        ])
        .arg(&out_obj)
        .status()?;
    if !status.success() {
        return Err(format!("clang failed building {:?}", out_obj).into());
    }

    println!("cargo:rustc-env=LURE_EBPF_OBJ={}", out_obj.display());
    println!("cargo:rustc-env=LURE_EBPF_ARCH={}", arch);
    Ok(())
}
