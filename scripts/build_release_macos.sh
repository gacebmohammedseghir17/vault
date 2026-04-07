#!/usr/bin/env bash
set -euo pipefail

# ERDPS Agent - macOS Release Build Script
# Builds optimized release binaries for macOS and collects artifacts into release/macos.
# Can optionally produce universal binaries (x86_64 + arm64) via lipo when both are built.

# Usage:
#   ./scripts/build_release_macos.sh [configuration] [universal|x86_64-apple-darwin|aarch64-apple-darwin] [--strip]
# Examples:
#   ./scripts/build_release_macos.sh                    # release, universal
#   ./scripts/build_release_macos.sh debug              # debug, universal
#   ./scripts/build_release_macos.sh release x86_64-apple-darwin --strip
#   ./scripts/build_release_macos.sh release universal --strip

CONFIGURATION=${1:-release}
TARGET_SPEC=${2:-universal}
STRIP=false
if [[ ${3:-} == "--strip" ]]; then STRIP=true; fi

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${AGENT_DIR}/.." && pwd)"
OUT_DIR_ROOT="${REPO_ROOT}/release/macos"

# Logging helpers
info() { echo -e "\033[0;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*"; }
success() { echo -e "\033[0;32m[SUCCESS]\033[0m $*"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Binaries to collect (extend as needed)
BIN_NAMES=(
  erdps-agent
  smoke_scan_cli
  metrics_report
)

# Determine which targets to build
TARGETS=()
case "$TARGET_SPEC" in
  universal)
    TARGETS=(x86_64-apple-darwin aarch64-apple-darwin)
    ;;
  x86_64-apple-darwin|aarch64-apple-darwin)
    TARGETS=($TARGET_SPEC)
    ;;
  *)
    error "Unknown target spec: $TARGET_SPEC"
    exit 2
    ;;
esac

info "Building ERDPS Agent (${CONFIGURATION}) for macOS targets: ${TARGETS[*]}"

# Ensure Rust targets are installed
for tgt in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -q "^${tgt}$"; then
    info "Installing Rust target: ${tgt}"
    rustup target add "${tgt}"
  fi
done

# Prepare output directories
mkdir -p "${OUT_DIR_ROOT}"
for tgt in "${TARGETS[@]}"; do
  mkdir -p "${OUT_DIR_ROOT}/${tgt}"
done

# Build features for production
export RUSTFLAGS="${RUSTFLAGS:-} --cfg tokio_unstable"

pushd "${AGENT_DIR}" >/dev/null
for tgt in "${TARGETS[@]}"; do
  CARGO_FLAGS=(build)
  if [[ "$CONFIGURATION" == "release" ]]; then CARGO_FLAGS+=(--release); fi
  CARGO_FLAGS+=(--target "$tgt")

  info "Running: cargo ${CARGO_FLAGS[*]} --features production"
  if ! cargo "${CARGO_FLAGS[@]}" --features production; then
    error "Cargo build failed for target $tgt"
    exit 1
  fi
done
popd >/dev/null

# Collect per-arch binaries
for tgt in "${TARGETS[@]}"; do
  TARGET_DIR="${AGENT_DIR}/target/${tgt}/${CONFIGURATION}"
  OUT_DIR_ARCH="${OUT_DIR_ROOT}/${tgt}"
  found_any=false
  for bin in "${BIN_NAMES[@]}"; do
    src_path="${TARGET_DIR}/${bin}"
    if [[ -f "${src_path}" ]]; then
      info "Copying ${bin} (${tgt}) -> ${OUT_DIR_ARCH}"
      cp -f "${src_path}" "${OUT_DIR_ARCH}/"
      found_any=true
    else
      warn "Binary not found: ${src_path}"
    fi
  done
  if [[ "${found_any}" != true ]]; then
    warn "No expected binaries were found in ${TARGET_DIR}"
  fi
done

# Optional strip to reduce size
if [[ "${STRIP}" == true ]]; then
  if command_exists strip; then
    info "Stripping per-arch binaries"
    for tgt in "${TARGETS[@]}"; do
      for f in "${OUT_DIR_ROOT}/${tgt}"/*; do
        if [[ -f "$f" && -x "$f" ]]; then
          strip -x "$f" || warn "strip failed for $f"
        fi
      done
    done
  else
    warn "strip not found; skipping binary stripping"
  fi
fi

# Create universal binaries if requested and both arch builds exist
if [[ "$TARGET_SPEC" == "universal" ]]; then
  if ! command_exists lipo; then
    warn "lipo not found; skipping universal binary creation"
  else
    info "Creating universal binaries with lipo"
    for bin in "${BIN_NAMES[@]}"; do
      BIN_X86="${OUT_DIR_ROOT}/x86_64-apple-darwin/${bin}"
      BIN_ARM="${OUT_DIR_ROOT}/aarch64-apple-darwin/${bin}"
      OUT_UNI="${OUT_DIR_ROOT}/${bin}"
      if [[ -f "${BIN_X86}" && -f "${BIN_ARM}" ]]; then
        info "lipo -create -output ${OUT_UNI} ${BIN_X86} ${BIN_ARM}"
        if lipo -create -output "${OUT_UNI}" "${BIN_X86}" "${BIN_ARM}"; then
          [[ "$STRIP" == true && -x "${OUT_UNI}" ]] && strip -x "${OUT_UNI}" || true
        else
          warn "Failed to create universal binary for ${bin}"
        fi
      else
        warn "Missing arch binaries for ${bin}; skipping universal creation"
      fi
    done
  fi
fi

success "macOS release build completed. Artifacts in: ${OUT_DIR_ROOT}"