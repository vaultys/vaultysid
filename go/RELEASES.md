# VaultysID CLI Releases

## Current status

No `vaultysid-cli` binary release has been published yet: there is no GitHub release carrying pre-compiled binaries, checksums, or a Docker image for the Go CLI, and no package-manager listing (Homebrew, APT, Snap, Chocolatey, Scoop) exists. `scripts/install.sh` and `scripts/install.ps1` at the repository root are wired to fetch `vaultysid-cli` from GitHub releases once one is published, but running them today will fail to find a release to download.

Until a release is published, build the CLI from source.

## Build from Source

### Requirements
- Go 1.21 or later
- Git

### Build Steps

```bash
git clone https://github.com/vaultys/vaultysid.git
cd vaultysid/go
make build-cli
```

The binary is written to `go/build/vaultysid-cli` (see the Makefile for the exact path). See [README.md](README.md) for usage and [cmd/vaultysid-cli/README.md](cmd/vaultysid-cli/README.md) for the full command reference.

## Support

- **Issues**: [GitHub Issues](https://github.com/vaultys/vaultysid/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vaultys/vaultysid/discussions)
- **Documentation**: [README.md](README.md)

## License

VaultysID CLI is released under the MIT License. See [LICENSE](../LICENSE) for details.
