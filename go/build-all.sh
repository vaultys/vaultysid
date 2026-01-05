#!/bin/bash

# VaultysID CLI Cross-Compilation Build Script
# Builds the CLI for all major operating systems and architectures

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Build configuration
BINARY_NAME="vaultysid-cli"
BUILD_DIR="dist"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS="-X main.Version=$VERSION -X main.Commit=$COMMIT -X main.BuildTime=$BUILD_TIME"

# Platforms to build for
# Format: GOOS/GOARCH/suffix
PLATFORMS=(
    # Linux
    "linux/amd64/"
    "linux/386/"
    "linux/arm64/"
    "linux/arm/v7"
    "linux/arm/v6"
    "linux/riscv64/"
    "linux/ppc64le/"
    "linux/s390x/"

    # macOS
    "darwin/amd64/"
    "darwin/arm64/"

    # Windows
    "windows/amd64/.exe"
    "windows/386/.exe"
    "windows/arm64/.exe"
    "windows/arm/.exe"

    # FreeBSD
    "freebsd/amd64/"
    "freebsd/386/"
    "freebsd/arm64/"
    "freebsd/arm/"

    # OpenBSD
    "openbsd/amd64/"
    "openbsd/386/"
    "openbsd/arm64/"
    "openbsd/arm/"

    # NetBSD
    "netbsd/amd64/"
    "netbsd/386/"
    "netbsd/arm64/"
    "netbsd/arm/"

    # Android (Termux)
    "android/arm64/"
    "android/amd64/"

    # iOS (experimental)
    "ios/arm64/"
    "ios/amd64/"

    # Solaris
    "solaris/amd64/"

    # Plan9
    "plan9/amd64/"
    "plan9/386/"
    "plan9/arm/"
)

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to build for a specific platform
build_platform() {
    local platform=$1
    IFS='/' read -r goos goarch suffix <<< "$platform"

    # Handle ARM versions
    local goarm=""
    if [[ "$goarch" == "arm" ]] && [[ "$suffix" == "v"* ]]; then
        goarm="${suffix:1:1}"
        suffix=""
    fi

    # Construct output filename
    local output_name="${BINARY_NAME}-${VERSION}-${goos}-${goarch}"
    if [[ -n "$goarm" ]]; then
        output_name="${output_name}v${goarm}"
    fi
    output_name="${output_name}${suffix}"
    local output_path="${BUILD_DIR}/${output_name}"

    # Set environment variables
    export GOOS=$goos
    export GOARCH=$goarch
    if [[ -n "$goarm" ]]; then
        export GOARM=$goarm
    fi

    # Try to build
    if go build -ldflags "$LDFLAGS" -o "$output_path" ./cmd/vaultysid-cli 2>/dev/null; then
        # Get file size
        local size=$(ls -lh "$output_path" | awk '{print $5}')
        print_color "$GREEN" "✓ Built: $output_name ($size)"
        return 0
    else
        print_color "$YELLOW" "⚠ Skipped: $goos/$goarch (unsupported)"
        return 1
    fi
}

# Function to create archives
create_archives() {
    print_color "$BLUE" "\n📦 Creating archives..."

    cd "$BUILD_DIR"

    for file in *; do
        if [[ -f "$file" ]]; then

            # Create tar.gz for Unix-like systems
            if [[ ! "$file" == *.exe ]]; then
                tar -czf "${file}.tar.gz" "$file"
                print_color "$GREEN" "✓ Created: ${file}.tar.gz"
                rm "$file"
            # Create zip for Windows
            else
                local base_name="${file%.*}"
                zip -q "${base_name}.zip" "$file"
                print_color "$GREEN" "✓ Created: ${base_name}.zip"
                rm "$file"
            fi
        fi
    done

    cd ..
}

# Function to generate checksums
generate_checksums() {
    print_color "$BLUE" "\n🔒 Generating checksums..."

    cd "$BUILD_DIR"

    # SHA256 checksums
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum *.{tar.gz,zip} 2>/dev/null > checksums-sha256.txt || true
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 *.{tar.gz,zip} 2>/dev/null > checksums-sha256.txt || true
    fi

    # SHA512 checksums
    if command -v sha512sum >/dev/null 2>&1; then
        sha512sum *.{tar.gz,zip} 2>/dev/null > checksums-sha512.txt || true
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 512 *.{tar.gz,zip} 2>/dev/null > checksums-sha512.txt || true
    fi

    if [[ -f checksums-sha256.txt ]]; then
        print_color "$GREEN" "✓ Generated: checksums-sha256.txt"
    fi

    if [[ -f checksums-sha512.txt ]]; then
        print_color "$GREEN" "✓ Generated: checksums-sha512.txt"
    fi

    cd ..
}

# Function to create version info file
create_version_info() {
    cat > "${BUILD_DIR}/version.json" <<EOF
{
    "version": "$VERSION",
    "commit": "$COMMIT",
    "build_time": "$BUILD_TIME",
    "go_version": "$(go version | cut -d' ' -f3)"
}
EOF
    print_color "$GREEN" "✓ Created: version.json"
}

# Main build process
main() {
    print_color "$BLUE" "======================================"
    print_color "$BLUE" "  VaultysID CLI Cross-Compilation"
    print_color "$BLUE" "======================================"
    echo
    print_color "$BLUE" "Version: $VERSION"
    print_color "$BLUE" "Commit: $COMMIT"
    print_color "$BLUE" "Build Time: $BUILD_TIME"
    echo

    # Check if Go is installed
    if ! command -v go >/dev/null 2>&1; then
        print_color "$RED" "Error: Go is not installed"
        exit 1
    fi

    # Check Go version (minimum 1.19 for better cross-compilation)
    GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
    MIN_VERSION="1.19"
    if [[ "$(printf '%s\n' "$MIN_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]]; then
        print_color "$YELLOW" "Warning: Go version $GO_VERSION is older than recommended $MIN_VERSION"
    fi

    # Clean and create build directory
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    # Download dependencies
    print_color "$BLUE" "📦 Downloading dependencies..."
    go mod download

    # Build for each platform
    print_color "$BLUE" "\n🔨 Building for all platforms..."
    echo

    local total=0
    local success=0
    local failed=0

    for platform in "${PLATFORMS[@]}"; do
        ((total++))
        if build_platform "$platform"; then
            ((success++))
        else
            ((failed++))
        fi
    done

    # Create archives
    create_archives

    # Generate checksums
    generate_checksums

    # Create version info
    create_version_info

    # Print summary
    echo
    print_color "$BLUE" "======================================"
    print_color "$BLUE" "  Build Summary"
    print_color "$BLUE" "======================================"
    print_color "$GREEN" "✓ Successful builds: $success"
    if [[ $failed -gt 0 ]]; then
        print_color "$YELLOW" "⚠ Skipped builds: $failed"
    fi
    print_color "$BLUE" "📁 Output directory: $BUILD_DIR/"
    echo

    # List all created files
    print_color "$BLUE" "📋 Created files:"
    ls -lh "$BUILD_DIR"/*.{tar.gz,zip,txt,json} 2>/dev/null | awk '{print "   " $9 " (" $5 ")"}'

    echo
    print_color "$GREEN" "✅ Build complete!"

    # Optional: Instructions for release
    if [[ -n "$GITHUB_ACTIONS" ]]; then
        echo
        print_color "$BLUE" "📤 Ready for GitHub release upload"
    else
        echo
        print_color "$BLUE" "💡 To create a GitHub release:"
        echo "   1. Create a new tag: git tag -a v$VERSION -m \"Release v$VERSION\""
        echo "   2. Push the tag: git push origin v$VERSION"
        echo "   3. Upload files from $BUILD_DIR/ to the GitHub release"
    fi
}

# Handle script arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --output)
            BUILD_DIR="$2"
            shift 2
            ;;
        --platforms)
            # Custom platforms list (comma-separated)
            IFS=',' read -ra PLATFORMS <<< "$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version VERSION    Set version string (default: git tag or 'dev')"
            echo "  --output DIR        Set output directory (default: dist)"
            echo "  --platforms LIST    Comma-separated list of GOOS/GOARCH pairs"
            echo "  --help             Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 --version v1.0.0"
            echo "  $0 --platforms linux/amd64,darwin/arm64,windows/amd64"
            exit 0
            ;;
        *)
            print_color "$RED" "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main build process
main
