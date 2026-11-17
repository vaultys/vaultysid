#!/bin/sh
set -eu

platform=${1:-}
case "$platform" in
    ios|android) ;;
    *) echo "Usage: $0 ios|android [output-directory]" >&2; exit 2 ;;
esac

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_dir=${2:-"$source_dir/bin/mobile"}
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/tools"
cd "$source_dir"
go build -o "$scratch/tools/gomobile" golang.org/x/mobile/cmd/gomobile
go build -o "$scratch/tools/gobind" golang.org/x/mobile/cmd/gobind
export PATH="$scratch/tools:$PATH"

licenses="$scratch/licenses"
mkdir -p "$licenses"
cp LICENSE "$licenses/Vaultys.txt"
cp "$(go env GOROOT)/LICENSE" "$licenses/Go.txt"
for module in github.com/RyuaNerin/elliptic2 github.com/aead/cmac github.com/fxamacker/cbor/v2 github.com/gmrtd/gmrtd github.com/x448/float16 golang.org/x/mobile; do
    module_dir=$(go list -m -f '{{.Dir}}' "$module")
    license_name=$(printf '%s' "$module" | tr '/' '-')
    cp "$module_dir/LICENSE" "$licenses/$license_name.txt"
done

if [ "$platform" = ios ]; then
    package="$scratch/VaultysPassport"
    mkdir -p "$package"
    cp -R mobile/ios/. "$package/"
    cp mobile/README.md LICENSE "$package/"
    cp -R "$licenses" "$package/"
    gomobile bind -target=ios,iossimulator -iosversion=15.0 -prefix=Vaultys \
        -ldflags=-X=runtime.godebugDefault=asyncpreemptoff=1 \
        -o "$package/VaultysPassportEngine.xcframework" ./mobile
    (cd "$scratch" && zip -qry "$scratch/vaultys-passport-ios.zip" VaultysPassport)
    mv "$scratch/vaultys-passport-ios.zip" "$output_dir/"
else
    : "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
    if [ -n "${JAVA_HOME:-}" ]; then
        export PATH="$JAVA_HOME/bin:$PATH"
    fi
    android_jar="$ANDROID_HOME/platforms/${ANDROID_PLATFORM:-android-36}/android.jar"
    if [ ! -f "$android_jar" ]; then
        echo "Android SDK platform not installed: $android_jar" >&2
        exit 2
    fi
    aar="$scratch/vaultys-passport-android.aar"
    gomobile bind -target=android/arm64,android/amd64 -androidapi=24 \
        -javapkg=io.vaultys.passport -ldflags=-R=16384 -o "$aar" ./mobile
    mkdir -p "$scratch/android/classes"
    unzip -p "$aar" classes.jar > "$scratch/android/classes.jar"
    javac --release 8 -classpath "$android_jar:$scratch/android/classes.jar" \
        -d "$scratch/android/classes" mobile/android/src/io/vaultys/passport/PassportTagReader.java
    jar uf "$scratch/android/classes.jar" -C "$scratch/android/classes" .
    cp mobile/android/AndroidManifest.xml mobile/android/proguard.txt "$scratch/android/"
    mkdir -p "$scratch/android/META-INF"
    cp -R "$licenses" "$scratch/android/META-INF/vaultys-passport-licenses"
    (cd "$scratch/android" && zip -qr "$aar" classes.jar AndroidManifest.xml proguard.txt META-INF)
    mv "$aar" "$output_dir/"
fi
