#!/usr/bin/env bash
set -euo pipefail

# Reproducible multi-target release pack builder for Lure.
#
# Outputs archives into ./dist/:
# - lure_<version>+<gitsha>_linux-amd64.tar.gz
# - lure_<version>+<gitsha>_linux-aarch64.tar.gz
# - lure_<version>+<gitsha>_linux-armv4.tar.gz
# - lure_<version>+<gitsha>_windows-amd64.zip
#
# Contents (per-archive):
# - lure[.exe]
# - tunure[.exe]
# - settings.toml
# - README.md
# - LICENSE
#
# Notes:
# - Uses cargo-zigbuild + zig for cross compilation. zig must be installed.
# - Uses SOURCE_DATE_EPOCH derived from the git commit timestamp for deterministic archives.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 1
    fi
}

need cargo
need rustup
need zig
need tar
need sha256sum
need zip
need python3

# cargo-zigbuild is invoked via `cargo zigbuild`; it doesn't support `--version`.
if ! cargo zigbuild --help >/dev/null 2>&1; then
    echo "installing cargo-zigbuild (cargo install --locked cargo-zigbuild)..." >&2
    cargo install --locked cargo-zigbuild
fi

version="$(
    cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
data = json.load(sys.stdin)
for p in data.get("packages", []):
    if p.get("name") == "lure":
        print(p.get("version", ""))
        break
'
)"
if [[ -z "${version}" ]]; then
    echo "failed to resolve lure version from cargo metadata" >&2
    exit 1
fi

gitsha="nogit"
epoch="0"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    gitsha="$(git rev-parse --short=12 HEAD)"
    epoch="$(git log -1 --format=%ct HEAD)"
fi

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$epoch}"

pack_base="lure_${version}+${gitsha}"
dist_dir="dist"
stage_root="${dist_dir}/.stage/${pack_base}"
target_dir="target-releasepack"

rm -rf "${stage_root}"
mkdir -p "${stage_root}" "${dist_dir}"

build_one() {
    local label="$1"
    local target="$2"
    local exe_suffix="$3"

    echo "==> building ${label} (${target})" >&2

    rustup target add "${target}" >/dev/null

    # Windows + clang (via zig) can fail building mimalloc due to `__DATE__`/`__TIME__` and
    # -Werror=date-time. Disable mimalloc for Windows packs.
    local lure_extra=()
    if [[ "${label}" == windows-* ]]; then
        lure_extra=(--no-default-features --features tokio_unstable)
    fi

    CARGO_TARGET_DIR="${target_dir}" cargo zigbuild \
        --release \
        --locked \
        --target "${target}" \
        -p lure --bin lure \
        "${lure_extra[@]}"

    CARGO_TARGET_DIR="${target_dir}" cargo zigbuild \
        --release \
        --locked \
        --target "${target}" \
        -p tun --bin tunure

    local out="${stage_root}/${label}"
    mkdir -p "${out}"

    install -m 0755 "${target_dir}/${target}/release/lure${exe_suffix}" "${out}/lure${exe_suffix}"
    install -m 0755 "${target_dir}/${target}/release/tunure${exe_suffix}" "${out}/tunure${exe_suffix}"
    install -m 0644 "settings.toml" "${out}/settings.toml"
    install -m 0644 "README.md" "${out}/README.md"
    install -m 0644 "LICENSE" "${out}/LICENSE"

    # Make archive mtimes deterministic.
    if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
        find "${out}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
    fi
}

make_targz() {
    local label="$1"
    local out_file="${dist_dir}/${pack_base}_${label}.tar.gz"
    local dir="${stage_root}/${label}"

    echo "==> packing ${out_file}" >&2
    tar \
        --sort=name \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        --owner=0 --group=0 --numeric-owner \
        -czf "${out_file}" \
        -C "${dir}" .
}

make_zip() {
    local label="$1"
    local out_file="${dist_dir}/${pack_base}_${label}.zip"
    local dir="${stage_root}/${label}"
    local out_abs
    out_abs="$(cd "${dist_dir}" && pwd)/${pack_base}_${label}.zip"

    echo "==> packing ${out_file}" >&2
    (
        cd "${dir}"
        # zip is deterministic when:
        # - file order is stable (we provide sorted list via stdin),
        # - mtimes are stable (we touched them above),
        # - extra fields excluded (-X).
        LC_ALL=C find . -print | LC_ALL=C sort | zip -X -9 "${out_abs}" -@
    )
}

# Targets requested by user.
# Note: "linux-armv4" maps to Rust's most compatible 32-bit ARM musl target.
build_one "linux-amd64" "x86_64-unknown-linux-musl" ""
build_one "linux-aarch64" "aarch64-unknown-linux-musl" ""
build_one "linux-armv4" "arm-unknown-linux-musleabi" ""
build_one "windows-amd64" "x86_64-pc-windows-gnu" ".exe"

make_targz "linux-amd64"
make_targz "linux-aarch64"
make_targz "linux-armv4"
make_zip "windows-amd64"

(
    cd "${dist_dir}"
    rm -f SHA256SUMS
    sha256sum "${pack_base}"_* > SHA256SUMS
)

echo "==> done: ${dist_dir}/${pack_base}_* and ${dist_dir}/SHA256SUMS" >&2
