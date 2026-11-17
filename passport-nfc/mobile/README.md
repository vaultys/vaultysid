# Vaultys Passport mobile libraries

The iOS and Android libraries read the passport's AA data groups and execute
the four AA commands used by `VaultysId.fromPassportAA()`. They share the
desktop reader's PACE, BAC, and secure messaging implementation. Your app owns
the NFC session, asks the user to present the passport, and bridges the reader
calls to its TypeScript code.

## Build or install

From `passport-nfc/`, use Go 1.26.10 or later. For iOS, install Xcode. For
Android, install JDK 17 or later, Android SDK Platform 36, and an Android NDK
such as r28c. Set `ANDROID_HOME`, `ANDROID_NDK_HOME`, and `JAVA_HOME` to
those installations.

```sh
./build-mobile.sh ios
./build-mobile.sh android
```

Find the packages in `bin/mobile/`.

- **iOS 15+**. Unzip `vaultys-passport-ios.zip` and add the `VaultysPassport`
  folder as a local Swift package. It includes a device arm64 XCFramework
  slice and simulator arm64 and x86_64 slices. Import `VaultysPassport`.
- **Android API 24+**. Add `vaultys-passport-android.aar` as a Gradle
  dependency using `implementation(files("libs/vaultys-passport-android.aar"))`.
  The AAR includes arm64-v8a and x86_64 native code. Import
  `io.vaultys.passport.PassportTagReader`.

## Connect to the NFC tag

On iOS, enable NFC Tag Reading for the host app. Add
`NFCReaderUsageDescription` to its Info.plist, and include
`A0000002471001` in
`com.apple.developer.nfc.readersession.iso7816.select-identifiers`. Start an
`NFCTagReaderSession` with ISO 14443 polling, connect to the
`NFCISO7816Tag`, and call the library away from your NFC delegate queue.

```swift
let groups = try await PassportTagReader.read(mrz: mrz, tag: tag)
let responses = try await PassportTagReader.sign(
    mrz: mrz, tag: signingTag, challenges: packedChallenges, responseLength: responseLength
)
```

On Android, use `NfcAdapter.enableReaderMode` in a foreground activity with
NFC-A, NFC-B and skip-NDEF-check flags. Pass the discovered ISO-DEP `Tag`
to the library from a worker thread. The Android library declares the NFC
permission and opens and closes the ISO-DEP connection.

```java
var groups = PassportTagReader.read(tag, mrz);
byte[] responses = PassportTagReader.sign(signingTag, mrz, packedChallenges, responseLength);
```

Use a fresh NFC session for each read or sign operation. Keep the passport in
the NFC field until the operation completes. The signed operation uses one
secure chip session for all four challenges.

## Bridge to VaultysID

Return the DG15 bytes and optional DG14 bytes to TypeScript from the native
read call. Pass them to `VaultysId.fromPassportAA()` with a local 32-byte
X25519 secret and a `reader` callback. The callback concatenates the four
eight-byte challenges, passes the 32 bytes and the expected response length
to the native sign call, then splits its result into four responses of that
length, in order. Transport these values as bytes, or encode them in base64
at the application bridge and decode them on the other side.

The native packages contain the reader libraries. Your host app supplies
the NFC scanning UI and any Capacitor plugin that exposes them to JavaScript.
Use a physical NFC-capable iPhone or Android device and a passport with an AA
key to test actual chip access.
