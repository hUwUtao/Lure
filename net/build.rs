fn main() {
    println!("cargo:rerun-if-changed=src/sock/epoll.c");
    println!("cargo:rerun-if-changed=src/sock/epoll.h");

    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "linux" {
        return;
    }

    cc::Build::new()
        .file("src/sock/epoll.c")
        .include("src/sock")
        .flag_if_supported("-O3")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .compile("lure_epoll");
}

