#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
data_root="${DNSDOH_BUILD_ROOT:-$project_root/.build}"
export CARGO_HOME="${CARGO_HOME:-$data_root/cache/cargo}"
export CARGO_TARGET_DIR="$project_root/target-musl"
export TMPDIR="${TMPDIR:-$data_root/tmp}"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-musl-gcc}"
mkdir -p "$CARGO_HOME" "$TMPDIR"
cd "$project_root"
# Use an installed Rust toolchain under RUSTUP_HOME; install musl-tools through your OS package manager.
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
printf 'Static agent: %s/x86_64-unknown-linux-musl/release/dnsdoh\n' "$CARGO_TARGET_DIR"
