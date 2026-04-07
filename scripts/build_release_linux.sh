#!/usr/bin/env bash
set -euo pipefail

# ERDPS Agent - Linux Release Build Script
# Builds optimized release binaries and collects them into repo-level release/linux

# Usage:
#   ./scripts/build_release_linux.sh [configuration] [target] [--strip]
# Examples:
#   ./scripts/build_release_linux.sh                 # release, native target
#   ./scripts/build_release_linux.sh debug           # debug, native target
#   ./scripts/build_release_linux.sh release aarch64-unknown-linux-gnu --strip

CONFIGURATION=${1:-release}
TARGET=${2:-native}
STRIP=false
if [[ ${3:-} == "--strip" ]]; then STRIP=true; fi

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${AGENT_DIR}/.." && pwd)"

# Logging helpers
info() { echo -e "\033[0;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*"; }
success() { echo -e "\033[0;32m[SUCCESS]\033[0m $*"; }

# Determine target dir layout
if [[ "$TARGET" == "native" ]]; then
  TARGET_DIR="${AGENT_DIR}/target/${CONFIGURATION}"
else
  TARGET_DIR="${AGENT_DIR}/target/${TARGET}/${CONFIGURATION}"
fi

OUT_DIR="${REPO_ROOT}/release/linux"

info "Building ERDPS Agent (${CONFIGURATION}) for target: ${TARGET}"

# Ensure rustup target installed when cross-compiling
if [[ "$TARGET" != "native" ]]; then
  if ! rustup target list --installed | grep -q "^${TARGET}$"; then
    info "Installing Rust target: ${TARGET}"
    rustup target add "${TARGET}"
  fi
fi

# Build features for production
export RUSTFLAGS="${RUSTFLAGS:-} --cfg tokio_unstable"

pushd "${AGENT_DIR}" >/dev/null
if [[ "$CONFIGURATION" == "release" ]]; then
  CARGO_FLAGS=(build --release)
else
  CARGO_FLAGS=(build)
fi

if [[ "$TARGET" != "native" ]]; then
  CARGO_FLAGS+=(--target "$TARGET")
fi

info "Running: cargo ${CARGO_FLAGS[*]} --features production"
if ! cargo "${CARGO_FLAGS[@]}" --features production; then
  error "Cargo build failed"
  exit 1
fi
popd >/dev/null

# Create output directory
mkdir -p "${OUT_DIR}"

# Binaries to collect (extend as needed)
BIN_NAMES=(
  erdps-agent
  smoke_scan_cli
  metrics_report
)

found_any=false
for bin in "${BIN_NAMES[@]}"; do
  src_path="${TARGET_DIR}/${bin}"
  if [[ -f "${src_path}" ]]; then
    info "Copying ${bin} -> ${OUT_DIR}"
    cp -f "${src_path}" "${OUT_DIR}/"
    found_any=true
  else
    warn "Binary not found: ${src_path}"
  fi
done

if [[ "${found_any}" != true ]]; then
  warn "No expected binaries were found in ${TARGET_DIR}."
fi

# Optional strip to reduce size
if [[ "${STRIP}" == true ]]; then
  if command -v strip >/dev/null 2>&1; then
    info "Stripping binaries"
    for f in "${OUT_DIR}"/*; do
      if [[ -f "$f" && -x "$f" ]]; then
        strip "$f" || warn "strip failed for $f"
      fi
    done
  else
    warn "strip not found; skipping binary stripping"
  fi
fi

success "Release build completed. Artifacts in: ${OUT_DIR}"