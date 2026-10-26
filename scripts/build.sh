#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
data_root="${DNSDOH_DATA_ROOT:-/mnt/youlin-data}"
export CARGO_HOME="${CARGO_HOME:-$data_root/cache/cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_root/target}"
export npm_config_cache="${npm_config_cache:-$data_root/cache/npm}"
export TMPDIR="${TMPDIR:-$data_root/tmp}"
mkdir -p "$CARGO_HOME" "$npm_config_cache" "$TMPDIR"
cd "$project_root/web"
npm ci --no-audit --no-fund
npm run build
cd "$project_root"
cargo fmt --check
cargo test --locked
cargo build --release --locked
printf 'Built executable: %s/release/dnsdoh\n' "$CARGO_TARGET_DIR"
