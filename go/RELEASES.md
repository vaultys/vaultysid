# VaultysID CLI Releases

## Overview

The VaultysID CLI is available as pre-compiled binaries for all major operating systems and architectures. This document provides detailed installation instructions and platform support information.

## 📥 Quick Install

### Unix/Linux/macOS (Shell)

```bash
curl -fsSL https://raw.githubusercontent.com/vaultys/vaultysid-go/main/scripts/install.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/vaultys/vaultysid-go/main/scripts/install.ps1 | iex
```

## 🖥️ Supported Platforms

| Operating System | Architecture | Binary Name | Status |
|-----------------|--------------|-------------|---------|
| **Linux** | | | |
| | amd64 (x86_64) | `vaultysid-cli-linux-amd64` | ✅ Full Support |
| | 386 (i386) | `vaultysid-cli-linux-386` | ✅ Full Support |
| | arm64 (aarch64) | `vaultysid-cli-linux-arm64` | ✅ Full Support |
| | arm/v7 | `vaultysid-cli-linux-armv7` | ✅ Full Support |
| | arm/v6 | `vaultysid-cli-linux-armv6` | ✅ Full Support |
| | riscv64 | `vaultysid-cli-linux-riscv64` | ✅ Full Support |
| | ppc64le | `vaultysid-cli-linux-ppc64le` | ✅ Full Support |
| | s390x | `vaultysid-cli-linux-s390x` | ✅ Full Support |
| **macOS** | | | |
| | amd64 (Intel) | `vaultysid-cli-darwin-amd64` | ✅ Full Support |
| | arm64 (Apple Silicon) | `vaultysid-cli-darwin-arm64` | ✅ Full Support |
| **Windows** | | | |
| | amd64 (x64) | `vaultysid-cli-windows-amd64.exe` | ✅ Full Support |
| | 386 (x86) | `vaultysid-cli-windows-386.exe` | ✅ Full Support |
| | arm64 | `vaultysid-cli-windows-arm64.exe` | ✅ Full Support |
| | arm | `vaultysid-cli-windows-arm.exe` | ⚠️ Experimental |
| **FreeBSD** | | | |
| | amd64 | `vaultysid-cli-freebsd-amd64` | ✅ Full Support |
| | 386 | `vaultysid-cli-freebsd-386` | ✅ Full Support |
| | arm64 | `vaultysid-cli-freebsd-arm64` | ✅ Full Support |
| | arm | `vaultysid-cli-freebsd-arm` | ⚠️ Experimental |
| **OpenBSD** | | | |
| | amd64 | `vaultysid-cli-openbsd-amd64` | ✅ Full Support |
| | 386 | `vaultysid-cli-openbsd-386` | ⚠️ Experimental |
| | arm64 | `vaultysid-cli-openbsd-arm64` | ⚠️ Experimental |
| | arm | `vaultysid-cli-openbsd-arm` | ⚠️ Experimental |
| **NetBSD** | | | |
| | amd64 | `vaultysid-cli-netbsd-amd64` | ⚠️ Experimental |
| | 386 | `vaultysid-cli-netbsd-386` | ⚠️ Experimental |
| | arm64 | `vaultysid-cli-netbsd-arm64` | ⚠️ Experimental |
| | arm | `vaultysid-cli-netbsd-arm` | ⚠️ Experimental |
| **Android** | | | |
| | arm64 | `vaultysid-cli-android-arm64` | ⚠️ Experimental |
| | amd64 | `vaultysid-cli-android-amd64` | ⚠️ Experimental |
| **Solaris** | | | |
| | amd64 | `vaultysid-cli-solaris-amd64` | ⚠️ Experimental |
| **Plan 9** | | | |
| | amd64 | `vaultysid-cli-plan9-amd64` | ⚠️ Experimental |
| | 386 | `vaultysid-cli-plan9-386` | ⚠️ Experimental |
| | arm | `vaultysid-cli-plan9-arm` | ⚠️ Experimental |

## 📦 Manual Installation

### Linux

#### AMD64 (x86_64)
```bash
VERSION="v1.0.0"  # Replace with desired version
curl -L "https://github.com/vaultys/vaultysid-go/releases/download/${VERSION}/vaultysid-cli-${VERSION}-linux-amd64.tar.gz" | tar xz
sudo mv vaultysid-cli-${VERSION}-linux-amd64 /usr/local/bin/vaultysid-cli
sudo chmod +x /usr/local/bin/vaultysid-cli
```

#### ARM64 (aarch64)
```bash
VERSION="v1.0.0"
curl -L "https://github.com/vaultys/vaultysid-go/releases/download/${VERSION}/vaultysid-cli-${VERSION}-linux-arm64.tar.gz" | tar xz
sudo mv vaultysid-cli-${VERSION}-linux-arm64 /usr/local/bin/vaultysid-cli
sudo chmod +x /usr/local/bin/vaultysid-cli
```

#### ARM v7 (32-bit ARM)
```bash
VERSION="v1.0.0"
curl -L "https://github.com/vaultys/vaultysid-go/releases/download/${VERSION}/vaultysid-cli-${VERSION}-linux-armv7.tar.gz" | tar xz
sudo mv vaultysid-cli-${VERSION}-linux-armv7 /usr/local/bin/vaultysid-cli
sudo chmod +x /usr/local/bin/vaultysid-cli
```

### macOS

#### Intel Mac
```bash
VERSION="v1.0.0"
curl -L "https://github.com/vaultys/vaultysid-go/releases/download/${VERSION}/vaultysid-cli-${VERSION}-darwin-amd64.tar.gz" | tar xz
sudo mv vaultysid-cli-${VERSION}-darwin-amd64 /usr/local/bin/vaultysid-cli
sudo chmod +x /usr/local/bin/vaultysid-cli
```

#### Apple Silicon (M1/M2/M3)
```bash
VERSION="v1.0.0"
curl -L "https://github.com/vaultys/vaultysid-go/releases/download/${VERSION}/vaultysid-cli-${VERSION}-darwin-arm64.tar.gz" | tar xz
sudo mv vaultysid-cli-${VERSION}-darwin-arm64 /usr/local/bin/vaultysid-cli
sudo chmod +x /usr/local/bin/vaultysid-cli
```

### Windows

#### Using PowerShell

```powershell
$VERSION = "v1.0.0"
$ARCH = "amd64"  # or "386", "arm64"

# Download
Invoke-WebRequest -Uri "https://github.com/vaultys/vaultysid-go/releases/download/$VERSION/vaultysid-cli-$VERSION-windows-$ARCH.exe.zip" -OutFile "vaultysid-cli.zip"

# Extract
Expand-Archive -Path "vaultysid-cli.zip" -DestinationPath "."

# Move to Program Files (requires admin)
New-Item -ItemType Directory -Force -Path "$env:ProgramFiles\VaultysID"
Move-Item -Path "vaultysid-cli-$VERSION-windows-$ARCH.exe" -Destination "$env:ProgramFiles\VaultysID\vaultysid-cli.exe"

# Add to PATH
$PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine")
[Environment]::SetEnvironmentVariable("PATH", "$PATH;$env:ProgramFiles\VaultysID", "Machine")
```

#### Using Command Prompt

```cmd
:: Download the ZIP file manually from GitHub releases
:: Extract to C:\Program Files\VaultysID\
:: Add C:\Program Files\VaultysID to your system PATH
```

### FreeBSD

```bash
VERSION="v1.0.0"
ARCH="amd64"  # or "386", "arm64", "arm"

fetch "https://github.com/vaultys/vaultysid-go/releases/download/${VERSION}/vaultysid-cli-${VERSION}-freebsd-${ARCH}.tar.gz"
tar -xzf "vaultysid-cli-${VERSION}-freebsd-${ARCH}.tar.gz"
sudo mv "vaultysid-cli-${VERSION}-freebsd-${ARCH}" /usr/local/bin/vaultysid-cli
sudo chmod +x /usr/local/bin/vaultysid-cli
```

## 🐳 Docker Installation

### Using Docker Hub

```bash
# Pull the image
docker pull vaultys/vaultysid-cli:latest

# Run the CLI
docker run --rm -it vaultys/vaultysid-cli --help

# Run with local files
docker run --rm -it -v $(pwd):/data vaultys/vaultysid-cli generate person -o json
```

### Using GitHub Container Registry

```bash
# Pull the image
docker pull ghcr.io/vaultys/vaultysid-cli:latest

# Run the CLI
docker run --rm -it ghcr.io/vaultys/vaultysid-cli --help
```

### Multi-architecture Support

Docker images are available for:
- `linux/amd64`
- `linux/arm64`
- `linux/arm/v7`

## 📦 Package Managers

### Homebrew (macOS/Linux)

```bash
# Coming soon
brew install vaultysid-cli
```

### APT (Debian/Ubuntu)

```bash
# Coming soon
sudo apt install vaultysid-cli
```

### YUM/DNF (RHEL/CentOS/Fedora)

```bash
# Coming soon
sudo dnf install vaultysid-cli
```

### Snap

```bash
# Coming soon
sudo snap install vaultysid-cli
```

### Chocolatey (Windows)

```powershell
# Coming soon
choco install vaultysid-cli
```

### Scoop (Windows)

```powershell
# Coming soon
scoop install vaultysid-cli
```

## 🔒 Verifying Downloads

All releases include SHA256 and SHA512 checksums for verification.

### Linux/macOS

```bash
# Download checksums
curl -L "https://github.com/vaultys/vaultysid-go/releases/download/v1.0.0/checksums-sha256.txt" -o checksums-sha256.txt

# Verify your download
sha256sum -c checksums-sha256.txt 2>/dev/null | grep OK
```

### Windows (PowerShell)

```powershell
# Download checksums
Invoke-WebRequest -Uri "https://github.com/vaultys/vaultysid-go/releases/download/v1.0.0/checksums-sha256.txt" -OutFile checksums-sha256.txt

# Calculate hash of your download
$hash = Get-FileHash -Path "vaultysid-cli-v1.0.0-windows-amd64.exe.zip" -Algorithm SHA256
$hash.Hash

# Compare with checksums file
Get-Content checksums-sha256.txt | Select-String "windows-amd64"
```

## 🚀 Post-Installation

### Verify Installation

```bash
# Check version
vaultysid-cli --version

# Show help
vaultysid-cli --help

# Generate a test identity
vaultysid-cli generate person -o json
```

### Shell Completion

#### Bash
```bash
vaultysid-cli completion bash > ~/.bash_completion.d/vaultysid-cli
source ~/.bashrc
```

#### Zsh
```bash
vaultysid-cli completion zsh > "${fpath[1]}/_vaultysid-cli"
source ~/.zshrc
```

#### Fish
```fish
vaultysid-cli completion fish > ~/.config/fish/completions/vaultysid-cli.fish
```

#### PowerShell
```powershell
vaultysid-cli completion powershell | Out-String | Invoke-Expression
```

## 🔄 Updating

### Using Installation Script

```bash
# Unix/Linux/macOS
curl -fsSL https://raw.githubusercontent.com/vaultys/vaultysid-go/main/scripts/install.sh | bash

# Windows PowerShell
irm https://raw.githubusercontent.com/vaultys/vaultysid-go/main/scripts/install.ps1 | iex
```

### Manual Update

Simply download the new version and replace the existing binary.

## ⚙️ Build from Source

### Requirements
- Go 1.19 or higher
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/vaultys/vaultysid-go.git
cd vaultysid-go/go

# Build for current platform
make build-cli

# Build for all platforms
make build-cross

# Install locally
make install-cli
```

## 🐛 Troubleshooting

### macOS Security Warning

If macOS blocks the binary:

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine /usr/local/bin/vaultysid-cli

# Or allow in System Preferences > Security & Privacy
```

### Linux Permission Denied

```bash
# Make executable
chmod +x /usr/local/bin/vaultysid-cli

# Check file permissions
ls -la /usr/local/bin/vaultysid-cli
```

### Windows Antivirus

Some antivirus software may flag the binary. You can:
1. Add an exception for `vaultysid-cli.exe`
2. Build from source to ensure authenticity
3. Verify checksums before installation

### PATH Issues

If the command is not found after installation:

```bash
# Linux/macOS
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc

# Windows (PowerShell as Administrator)
[Environment]::SetEnvironmentVariable("PATH", "$env:PATH;C:\Program Files\VaultysID", "Machine")
```

## 📝 Release Notes

See [CHANGELOG.md](https://github.com/vaultys/vaultysid-go/blob/main/go/CHANGELOG.md) for detailed release notes.

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/vaultys/vaultysid-go/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vaultys/vaultysid-go/discussions)
- **Documentation**: [README.md](https://github.com/vaultys/vaultysid-go/blob/main/go/README.md)

## 📄 License

VaultysID CLI is released under the MIT License. See [LICENSE](https://github.com/vaultys/vaultysid-go/blob/main/LICENSE) for details.