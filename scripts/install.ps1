# VaultysID CLI Installation Script for Windows
# PowerShell script to download and install VaultysID CLI

param(
    [Parameter(Mandatory=$false)]
    [string]$Version = "",

    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\VaultysID",

    [Parameter(Mandatory=$false)]
    [switch]$AddToPath = $true,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Configuration
$GithubRepo = "vaultys/vaultysid"
$BinaryName = "vaultysid-cli"

# Colors and formatting
function Write-Color {
    param(
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    $previousColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $previousColor
}

function Write-Success {
    param([string]$Message)
    Write-Color "✓ $Message" Green
}

function Write-Info {
    param([string]$Message)
    Write-Color "→ $Message" Cyan
}

function Write-Warning {
    param([string]$Message)
    Write-Color "⚠ $Message" Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Color "Error: $Message" Red
    exit 1
}

# Show help
if ($Help) {
    Write-Host @"
VaultysID CLI Installer for Windows

Usage: .\install.ps1 [OPTIONS]

Options:
    -Version <string>      Install specific version (default: latest)
    -InstallDir <string>   Installation directory (default: $env:LOCALAPPDATA\Programs\VaultysID)
    -AddToPath             Add to system PATH (default: true)
    -Help                  Show this help message

Examples:
    .\install.ps1                              # Install latest version
    .\install.ps1 -Version "v1.0.0"           # Install specific version
    .\install.ps1 -InstallDir "C:\Tools"      # Install to custom directory
    .\install.ps1 -AddToPath:$false           # Don't add to PATH

Requirements:
    - PowerShell 5.0 or higher
    - Internet connection to download from GitHub
    - Administrator privileges (if adding to system PATH)
"@
    exit 0
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.0 or higher is required. Current version: $($PSVersionTable.PSVersion)"
}

Write-Host ""
Write-Color "======================================" Blue
Write-Color "  VaultysID CLI Installer for Windows" Blue
Write-Color "======================================" Blue
Write-Host ""

# Enable TLS 1.2 for GitHub API
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Detect architecture
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "x86" { return "386" }
        "ARM64" { return "arm64" }
        "ARM" { return "arm" }
        default {
            Write-Error "Unsupported architecture: $arch"
        }
    }
}

# Get latest version from GitHub
function Get-LatestVersion {
    Write-Info "Fetching latest version..."

    try {
        $apiUrl = "https://api.github.com/repos/$GithubRepo/releases/latest"
        $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $version = $response.tag_name

        # Remove 'v' or 'go-' prefix if present
        $version = $version -replace '^v', '' -replace '^go-', ''

        Write-Success "Latest version: $version"
        return $version
    }
    catch {
        Write-Error "Failed to fetch latest version: $_"
    }
}

# Download file with progress
function Download-File {
    param(
        [string]$Url,
        [string]$OutFile
    )

    Write-Info "Downloading from: $Url"

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
        $ProgressPreference = 'Continue'

        if (Test-Path $OutFile) {
            $size = (Get-Item $OutFile).Length
            $sizeMB = [Math]::Round($size / 1MB, 2)
            Write-Success "Downloaded: $sizeMB MB"
            return $true
        }
        return $false
    }
    catch {
        Write-Error "Download failed: $_"
        return $false
    }
}

# Extract ZIP file
function Extract-Archive {
    param(
        [string]$Path,
        [string]$DestinationPath
    )

    Write-Info "Extracting archive..."

    try {
        # Use built-in Expand-Archive for PowerShell 5.0+
        Expand-Archive -Path $Path -DestinationPath $DestinationPath -Force
        Write-Success "Extraction complete"
        return $true
    }
    catch {
        Write-Error "Extraction failed: $_"
        return $false
    }
}

# Add to PATH
function Add-ToPath {
    param([string]$Path)

    Write-Info "Adding to PATH..."

    $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)

    if ($currentPath -notlike "*$Path*") {
        try {
            # Check if running as administrator
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

            if ($isAdmin) {
                # Add to system PATH
                $target = [EnvironmentVariableTarget]::Machine
                $currentSystemPath = [Environment]::GetEnvironmentVariable("Path", $target)
                $newPath = "$currentSystemPath;$Path"
                [Environment]::SetEnvironmentVariable("Path", $newPath, $target)
                Write-Success "Added to system PATH (requires new terminal)"
            }
            else {
                # Add to user PATH
                $target = [EnvironmentVariableTarget]::User
                $newPath = "$currentPath;$Path"
                [Environment]::SetEnvironmentVariable("Path", $newPath, $target)
                Write-Success "Added to user PATH (requires new terminal)"
            }

            # Also update current session
            $env:Path = "$env:Path;$Path"

            return $true
        }
        catch {
            Write-Warning "Failed to add to PATH: $_"
            return $false
        }
    }
    else {
        Write-Info "Already in PATH"
        return $true
    }
}

# Main installation
function Install-VaultysIDCLI {
    # Get architecture
    $arch = Get-Architecture
    Write-Info "Detected architecture: $arch"

    # Get version
    if ([string]::IsNullOrEmpty($Version)) {
        $Version = Get-LatestVersion
    }
    else {
        $Version = $Version -replace '^v', '' -replace '^go-', ''
        Write-Info "Installing version: $Version"
    }

    # Construct download URL
    $fileName = "$BinaryName-$Version-windows-$arch.exe.zip"
    $downloadUrl = "https://github.com/$GithubRepo/releases/download/v$Version/$fileName"

    # Create temp directory
    $tempDir = Join-Path $env:TEMP "vaultysid-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        # Download archive
        $archivePath = Join-Path $tempDir $fileName
        if (-not (Download-File -Url $downloadUrl -OutFile $archivePath)) {
            throw "Download failed"
        }

        # Extract archive
        if (-not (Extract-Archive -Path $archivePath -DestinationPath $tempDir)) {
            throw "Extraction failed"
        }

        # Find the executable
        $exeName = "$BinaryName-$Version-windows-$arch.exe"
        $exePath = Join-Path $tempDir $exeName

        if (-not (Test-Path $exePath)) {
            # Try without version in name
            $exeName = "$BinaryName.exe"
            $exePath = Join-Path $tempDir $exeName

            if (-not (Test-Path $exePath)) {
                # List directory contents for debugging
                Write-Warning "Expected executable not found. Directory contents:"
                Get-ChildItem $tempDir | ForEach-Object { Write-Host "  $_" }

                # Try to find any .exe file
                $exeFiles = Get-ChildItem -Path $tempDir -Filter "*.exe"
                if ($exeFiles.Count -eq 1) {
                    $exePath = $exeFiles[0].FullName
                    $exeName = $exeFiles[0].Name
                    Write-Info "Found executable: $exeName"
                }
                else {
                    throw "Executable not found in archive"
                }
            }
        }

        # Create install directory
        Write-Info "Creating installation directory: $InstallDir"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

        # Copy executable
        $destPath = Join-Path $InstallDir "$BinaryName.exe"
        Write-Info "Installing to: $destPath"
        Copy-Item -Path $exePath -Destination $destPath -Force

        Write-Success "Installation complete"

        # Add to PATH if requested
        if ($AddToPath) {
            Add-ToPath -Path $InstallDir
        }

        # Verify installation
        Write-Info "Verifying installation..."

        $testPath = Join-Path $InstallDir "$BinaryName.exe"
        if (Test-Path $testPath) {
            try {
                $versionOutput = & $testPath --version 2>&1
                Write-Success "VaultysID CLI installed successfully!"

                if ($AddToPath) {
                    Write-Host ""
                    Write-Warning "PATH has been updated. Please restart your terminal or run:"
                    Write-Host '  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User")'
                    Write-Host ""
                }

                Write-Info "Run '$BinaryName --help' to get started"
            }
            catch {
                Write-Warning "Installation complete but unable to verify version"
            }
        }
        else {
            Write-Error "Installation verification failed"
        }
    }
    finally {
        # Cleanup
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Create uninstall script
function Create-UninstallScript {
    $uninstallPath = Join-Path $InstallDir "uninstall.ps1"

    $uninstallScript = @"
# VaultysID CLI Uninstaller
Write-Host "Uninstalling VaultysID CLI..."

# Remove from PATH
`$userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
`$newPath = (`$userPath -split ';' | Where-Object { `$_ -ne '$InstallDir' }) -join ';'
[Environment]::SetEnvironmentVariable("Path", `$newPath, [EnvironmentVariableTarget]::User)

# Remove installation directory
Remove-Item -Path '$InstallDir' -Recurse -Force

Write-Host "VaultysID CLI has been uninstalled."
"@

    Set-Content -Path $uninstallPath -Value $uninstallScript
    Write-Info "Uninstaller created: $uninstallPath"
}

# Run installation
try {
    Install-VaultysIDCLI
    Create-UninstallScript

    Write-Host ""
    Write-Color "======================================" Green
    Write-Color "  Installation Complete!" Green
    Write-Color "======================================" Green
    Write-Host ""
}
catch {
    Write-Error "$_"
}
