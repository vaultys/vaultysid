#!/bin/bash

# VaultysID CLI Installation Script for Unix-like Systems
# Supports: Linux, macOS, FreeBSD, OpenBSD, NetBSD

set -e

# Configuration
GITHUB_REPO="vaultys/vaultysid"
BINARY_NAME="vaultysid-cli"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_color() {
    echo -e "${1}${2}${NC}"
}

error() {
    print_color "$RED" "Error: $1" >&2
    exit 1
}

success() {
    print_color "$GREEN" "✓ $1"
}

info() {
    print_color "$BLUE" "→ $1"
}

warning() {
    print_color "$YELLOW" "⚠ $1"
}

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux*)
            OS="linux"
            ;;
        darwin*)
            OS="darwin"
            ;;
        freebsd*)
            OS="freebsd"
            ;;
        openbsd*)
            OS="openbsd"
            ;;
        netbsd*)
            OS="netbsd"
            ;;
        *)
            error "Unsupported operating system: $OS"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        i386|i686)
            ARCH="386"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv7)
            ARCH="arm"
            ARM_VERSION="v7"
            ;;
        armv6l|armv6)
            ARCH="arm"
            ARM_VERSION="v6"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    if [[ "$ARCH" == "arm" ]] && [[ -n "$ARM_VERSION" ]]; then
        PLATFORM="${PLATFORM}${ARM_VERSION}"
    fi

    info "Detected platform: $PLATFORM"
}

# Check for required tools
check_requirements() {
    local missing_tools=()

    for tool in curl tar; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        error "Missing required tools: ${missing_tools[*]}. Please install them and try again."
    fi
}

# Get latest release version from GitHub
get_latest_version() {
    info "Fetching latest version..."

    if command -v curl &> /dev/null; then
        VERSION=$(curl -sL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        error "curl is required to fetch the latest version"
    fi

    if [ -z "$VERSION" ]; then
        error "Failed to fetch latest version"
    fi

    # Remove 'v' prefix if present
    VERSION="${VERSION#v}"
    VERSION="${VERSION#go-}"

    success "Latest version: $VERSION"
}

# Download and install binary
download_and_install() {
    local download_url="https://github.com/$GITHUB_REPO/releases/download/v${VERSION}/${BINARY_NAME}-${VERSION}-${PLATFORM}.tar.gz"
    local temp_dir=$(mktemp -d)
    local archive_path="${temp_dir}/${BINARY_NAME}.tar.gz"
    local binary_path="${temp_dir}/${BINARY_NAME}-${VERSION}-${PLATFORM}"

    info "Downloading from: $download_url"

    # Download the archive
    if ! curl -L -o "$archive_path" "$download_url"; then
        rm -rf "$temp_dir"
        error "Failed to download binary"
    fi

    # Extract the archive
    info "Extracting archive..."
    if ! tar -xzf "$archive_path" -C "$temp_dir"; then
        rm -rf "$temp_dir"
        error "Failed to extract archive"
    fi

    # Check if binary exists
    if [ ! -f "$binary_path" ]; then
        # Try without version in filename
        binary_path="${temp_dir}/${BINARY_NAME}"
        if [ ! -f "$binary_path" ]; then
            ls -la "$temp_dir"
            rm -rf "$temp_dir"
            error "Binary not found in archive"
        fi
    fi

    # Make binary executable
    chmod +x "$binary_path"

    # Check if we need sudo for installation
    local use_sudo=""
    if [ ! -w "$INSTALL_DIR" ]; then
        if command -v sudo &> /dev/null; then
            info "Administrator privileges required for installation to $INSTALL_DIR"
            use_sudo="sudo"
        else
            warning "Cannot write to $INSTALL_DIR and sudo is not available"
            INSTALL_DIR="$HOME/.local/bin"
            mkdir -p "$INSTALL_DIR"
            warning "Installing to $INSTALL_DIR instead"
        fi
    fi

    # Install the binary
    info "Installing to $INSTALL_DIR..."
    $use_sudo mv "$binary_path" "$INSTALL_DIR/$BINARY_NAME"
    $use_sudo chmod 755 "$INSTALL_DIR/$BINARY_NAME"

    # Clean up
    rm -rf "$temp_dir"

    success "Installation complete!"
}

# Verify installation
verify_installation() {
    if ! command -v "$BINARY_NAME" &> /dev/null; then
        warning "$BINARY_NAME is installed but not in PATH"
        info "Add $INSTALL_DIR to your PATH:"
        echo
        echo "  For bash:"
        echo "    echo 'export PATH=\$PATH:$INSTALL_DIR' >> ~/.bashrc"
        echo "    source ~/.bashrc"
        echo
        echo "  For zsh:"
        echo "    echo 'export PATH=\$PATH:$INSTALL_DIR' >> ~/.zshrc"
        echo "    source ~/.zshrc"
        echo
        echo "  For fish:"
        echo "    set -U fish_user_paths $INSTALL_DIR \$fish_user_paths"
        echo
    else
        local installed_version=$($BINARY_NAME version 2>/dev/null || echo "unknown")
        success "$BINARY_NAME installed successfully!"
        info "Version: $installed_version"
        info "Run '$BINARY_NAME --help' to get started"
    fi
}

# Main installation flow
main() {
    echo
    print_color "$BLUE" "======================================"
    print_color "$BLUE" "  VaultysID CLI Installer"
    print_color "$BLUE" "======================================"
    echo

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  --version VERSION     Install specific version (default: latest)"
                echo "  --install-dir DIR     Installation directory (default: /usr/local/bin)"
                echo "  --help               Show this help message"
                echo
                echo "Examples:"
                echo "  $0                           # Install latest version"
                echo "  $0 --version v1.0.0          # Install specific version"
                echo "  $0 --install-dir ~/bin       # Install to custom directory"
                exit 0
                ;;
            *)
                error "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done

    # Run installation steps
    check_requirements
    detect_platform

    if [ -z "$VERSION" ]; then
        get_latest_version
    else
        # Remove 'v' prefix if provided
        VERSION="${VERSION#v}"
        info "Installing version: $VERSION"
    fi

    download_and_install
    verify_installation

    echo
    print_color "$GREEN" "======================================"
    print_color "$GREEN" "  Installation Complete!"
    print_color "$GREEN" "======================================"
    echo
}

# Run main function
main "$@"
