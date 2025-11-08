#!/bin/bash

# VaultysId Rust Build Script
# This script compiles, tests, and runs examples for the VaultysId Rust implementation

set -e  # Exit on error

echo "🔨 Building VaultysId Rust Library..."
echo "======================================="

# Clean previous builds
echo "📦 Cleaning previous builds..."
cargo clean

# Build the library
echo "🏗️  Building library..."
cargo build --release

# Run all tests
echo ""
echo "🧪 Running tests..."
echo "==================="
cargo test --lib --release

# Run integration tests
echo ""
echo "🔄 Running integration tests..."
cargo test --test integration_tests --release

# Check code formatting
echo ""
echo "📝 Checking code format..."
echo "=========================="
cargo fmt -- --check || echo "⚠️  Code needs formatting. Run 'cargo fmt' to fix."

# Run clippy for lints
echo ""
echo "🔍 Running clippy..."
echo "===================="
cargo clippy -- -D warnings || echo "⚠️  Clippy found issues."

# Build documentation
echo ""
echo "📚 Building documentation..."
echo "============================"
cargo doc --no-deps

# Run example if requested
if [ "$1" = "--example" ]; then
    echo ""
    echo "🚀 Running example..."
    echo "====================="
    cargo run --example basic_usage --release
fi

# Run benchmarks if requested
if [ "$1" = "--bench" ]; then
    echo ""
    echo "⚡ Running benchmarks..."
    echo "========================"
    cargo bench
fi

echo ""
echo "✅ Build completed successfully!"
echo ""
echo "📊 Build Summary:"
echo "  - Library: ✅ Built"
echo "  - Tests: ✅ Passed"
echo "  - Documentation: ✅ Generated"
echo ""
echo "📁 Output locations:"
echo "  - Binary: target/release/"
echo "  - Documentation: target/doc/"
echo ""
echo "💡 Tips:"
echo "  - Run './build.sh --example' to see the example in action"
echo "  - Run './build.sh --bench' to run performance benchmarks"
echo "  - Open 'target/doc/vaultysid/index.html' to view documentation"
