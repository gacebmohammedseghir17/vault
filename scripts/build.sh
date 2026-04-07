#!/bin/bash
#
# ERDPS Agent Build Script
#
# This script automates the build process for the ERDPS Agent with YARA scanner support.
# It handles dependency detection, environment setup, and cross-compilation.
#
# Usage:
#   ./scripts/build.sh [BUILD_TYPE] [TARGET] [FEATURES]
#
# Examples:
#   ./scripts/build.sh                                    # Default: release native yara,production
#   ./scripts/build.sh debug                             # Debug build
#   ./scripts/build.sh release x86_64-pc-windows-gnu     # Cross-compile to Windows
#   ./scripts/build.sh release native "yara,production"   # Explicit features

set -euo pipefail

# Configuration
BUILD_TYPE=${1:-release}
TARGET=${2:-native}
FEATURES=${3:-yara,production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect operating system
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "macos";;
        CYGWIN*)    echo "windows";;
        MINGW*)     echo "windows";;
        MSYS*)      echo "windows";;
        *)          echo "unknown";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64)     echo "x86_64";;
        aarch64)    echo "aarch64";;
        arm64)      echo "aarch64";;
        armv7l)     echo "armv7";;
        i686)       echo "i686";;
        *)          echo "unknown";;
    esac
}

# Check Rust installation
check_rust() {
    log_info "Checking Rust installation..."
    
    if ! command_exists rustc; then
        log_error "Rust is not installed. Please install Rust from https://rustup.rs/"
        exit 1
    fi
    
    local rust_version
    rust_version=$(rustc --version | cut -d' ' -f2)
    log_info "Found Rust version: $rust_version"
    
    # Check minimum Rust version (1.70.0)
    local min_version="1.70.0"
    if ! printf '%s\n%s\n' "$min_version" "$rust_version" | sort -V -C; then
        log_warn "Rust version $rust_version is older than recommended minimum $min_version"
    fi
}

# Check and install Rust target
check_rust_target() {
    local target="$1"
    
    if [ "$target" = "native" ]; then
        return 0
    fi
    
    log_info "Checking Rust target: $target"
    
    if ! rustup target list --installed | grep -q "^$target$"; then
        log_info "Installing Rust target: $target"
        rustup target add "$target"
    else
        log_info "Rust target $target is already installed"
    fi
}

# Check YARA installation
check_yara() {
    log_info "Checking YARA installation..."
    
    # Skip YARA check if not using YARA features
    if [[ "$FEATURES" != *"yara"* ]]; then
        log_info "YARA features not enabled, skipping YARA check"
        return 0
    fi
    
    # Check pkg-config first
    if command_exists pkg-config && pkg-config --exists yara; then
        local yara_version
        yara_version=$(pkg-config --modversion yara)
        log_success "Found YARA via pkg-config: version $yara_version"
        return 0
    fi
    
    # Check for YARA library files
    local os
    os=$(detect_os)
    
    case "$os" in
        linux)
            local lib_paths=("/usr/lib" "/usr/local/lib" "/usr/lib/x86_64-linux-gnu" "/usr/lib64")
            for path in "${lib_paths[@]}"; do
                if [ -f "$path/libyara.so" ]; then
                    log_success "Found YARA library at: $path/libyara.so"
                    export YARA_LIBRARY_PATH="$path"
                    return 0
                fi
            done
            ;;
        macos)
            local lib_paths=("/usr/local/lib" "/opt/homebrew/lib")
            for path in "${lib_paths[@]}"; do
                if [ -f "$path/libyara.dylib" ]; then
                    log_success "Found YARA library at: $path/libyara.dylib"
                    export YARA_LIBRARY_PATH="$path"
                    return 0
                fi
            done
            ;;
    esac
    
    # Check environment variables
    if [ -n "${YARA_LIBRARY_PATH:-}" ] && [ -d "$YARA_LIBRARY_PATH" ]; then
        log_success "Using YARA from YARA_LIBRARY_PATH: $YARA_LIBRARY_PATH"
        return 0
    fi
    
    log_error "YARA library not found!"
    log_info "Please install YARA using one of these methods:"
    case "$os" in
        linux)
            log_info "  Ubuntu/Debian: sudo apt-get install libyara-dev"
            log_info "  CentOS/RHEL: sudo yum install yara-devel"
            log_info "  Or build from source: https://github.com/VirusTotal/yara"
            ;;
        macos)
            log_info "  Homebrew: brew install yara"
            log_info "  Or build from source: https://github.com/VirusTotal/yara"
            ;;
    esac
    log_info "  Or set YARA_LIBRARY_PATH environment variable"
    
    return 1
}

# Setup cross-compilation environment
setup_cross_compilation() {
    local target="$1"
    local os
    os=$(detect_os)
    
    if [ "$target" = "native" ]; then
        return 0
    fi
    
    log_info "Setting up cross-compilation for target: $target"
    
    case "$target" in
        x86_64-pc-windows-gnu)
            if [ "$os" = "linux" ]; then
                # Check for MinGW cross-compiler
                if ! command_exists x86_64-w64-mingw32-gcc; then
                    log_error "MinGW cross-compiler not found!"
                    log_info "Install with: sudo apt-get install gcc-mingw-w64-x86-64"
                    return 1
                fi
                
                export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
                export CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++
                export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
                export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
                
                log_success "Cross-compilation environment set up for Windows"
            else
                log_warn "Cross-compilation to Windows from $os may not be fully supported"
            fi
            ;;
        aarch64-unknown-linux-gnu)
            if [ "$os" = "linux" ]; then
                if ! command_exists aarch64-linux-gnu-gcc; then
                    log_error "ARM64 cross-compiler not found!"
                    log_info "Install with: sudo apt-get install gcc-aarch64-linux-gnu"
                    return 1
                fi
                
                export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
                export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
                export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
                export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
                
                log_success "Cross-compilation environment set up for ARM64 Linux"
            fi
            ;;
        *)
            log_warn "Cross-compilation setup for target $target is not automated"
            log_info "You may need to set up the environment manually"
            ;;
    esac
}

# Setup build environment
setup_environment() {
    log_info "Setting up build environment..."
    
    # Set optimization flags
    case "$BUILD_TYPE" in
        release)
            export RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native -C lto=fat"
            ;;
        debug)
            export RUSTFLAGS="${RUSTFLAGS:-} -C debuginfo=2"
            ;;
    esac
    
    # Enable parallel compilation
    if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
        local num_cores
        if command_exists nproc; then
            num_cores=$(nproc)
        elif [ -f /proc/cpuinfo ]; then
            num_cores=$(grep -c ^processor /proc/cpuinfo)
        else
            num_cores=4
        fi
        export CARGO_BUILD_JOBS="$num_cores"
    fi
    
    log_info "Using $CARGO_BUILD_JOBS parallel build jobs"
    log_info "RUSTFLAGS: ${RUSTFLAGS:-<not set>}"
}

# Build the project
build_project() {
    log_info "Building ERDPS Agent..."
    log_info "  Build type: $BUILD_TYPE"
    log_info "  Target: $TARGET"
    log_info "  Features: $FEATURES"
    
    cd "$PROJECT_ROOT"
    
    local cargo_args=("build")
    
    # Add build type
    if [ "$BUILD_TYPE" = "release" ]; then
        cargo_args+=("--release")
    fi
    
    # Add target
    if [ "$TARGET" != "native" ]; then
        cargo_args+=("--target" "$TARGET")
    fi
    
    # Add features
    if [ -n "$FEATURES" ]; then
        cargo_args+=("--features" "$FEATURES")
    fi
    
    # Run cargo build
    log_info "Running: cargo ${cargo_args[*]}"
    
    local start_time
    start_time=$(date +%s)
    
    if cargo "${cargo_args[@]}"; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_success "Build completed successfully in ${duration}s"
        
        # Show binary information
        show_binary_info
    else
        log_error "Build failed!"
        return 1
    fi
}

# Show binary information
show_binary_info() {
    local binary_path
    
    if [ "$TARGET" = "native" ]; then
        binary_path="target/$BUILD_TYPE/erdps-agent"
    else
        binary_path="target/$TARGET/$BUILD_TYPE/erdps-agent"
    fi
    
    # Add .exe extension for Windows targets
    if [[ "$TARGET" == *"windows"* ]]; then
        binary_path="${binary_path}.exe"
    fi
    
    if [ -f "$binary_path" ]; then
        log_info "Binary information:"
        log_info "  Path: $binary_path"
        
        if command_exists ls; then
            local size
            size=$(ls -lh "$binary_path" | awk '{print $5}')
            log_info "  Size: $size"
        fi
        
        if command_exists file; then
            local file_info
            file_info=$(file "$binary_path")
            log_info "  Type: $file_info"
        fi
        
        # Check dependencies (Linux only)
        if [[ "$TARGET" == *"linux"* ]] && command_exists ldd; then
            log_info "  Dependencies:"
            ldd "$binary_path" | head -10 | while read -r line; do
                log_info "    $line"
            done
        fi
    else
        log_warn "Binary not found at expected path: $binary_path"
    fi
}

# Run tests
run_tests() {
    if [ "${RUN_TESTS:-true}" = "true" ]; then
        log_info "Running tests..."
        
        local cargo_args=("test")
        
        # Add target
        if [ "$TARGET" != "native" ]; then
            cargo_args+=("--target" "$TARGET")
        fi
        
        # Add features
        if [ -n "$FEATURES" ]; then
            cargo_args+=("--features" "$FEATURES")
        fi
        
        if cargo "${cargo_args[@]}"; then
            log_success "All tests passed!"
        else
            log_warn "Some tests failed"
        fi
    fi
}

# Main function
main() {
    log_info "ERDPS Agent Build Script"
    log_info "========================"
    
    # Validate arguments
    case "$BUILD_TYPE" in
        debug|release) ;;
        *) log_error "Invalid build type: $BUILD_TYPE (must be 'debug' or 'release')"; exit 1 ;;
    esac
    
    # Check prerequisites
    check_rust
    check_rust_target "$TARGET"
    
    # Setup environment
    setup_environment
    setup_cross_compilation "$TARGET"
    
    # Check YARA if needed
    if ! check_yara; then
        if [[ "$FEATURES" == *"yara"* ]]; then
            log_error "YARA is required for the requested features but not found"
            log_info "Either install YARA or build without YARA features:"
            log_info "  $0 $BUILD_TYPE $TARGET ''"
            exit 1
        fi
    fi
    
    # Build project
    build_project
    
    # Run tests
    run_tests
    
    log_success "Build process completed successfully!"
    log_info "Binary location: target/$([[ "$TARGET" != "native" ]] && echo "$TARGET/")$BUILD_TYPE/erdps-agent$([[ "$TARGET" == *"windows"* ]] && echo ".exe")"
}

# Run main function
main "$@"