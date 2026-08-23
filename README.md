# opaque-swift

RFC 9807 OPAQUE client support for Swift, backed by Rust [`opaque-ke`](https://github.com/facebook/opaque-ke) 4.0.1.

The public API uses `Data`. It does not depend on BLE, HTTP, or another transport. You can move the OPAQUE messages over CoreBluetooth, Network.framework, a socket, or another channel.

## Crypto suite

This package currently fixes one suite so Swift and the server cannot accidentally select different parameters:

- OPRF: Ristretto255
- Key exchange: TripleDH with Ristretto255 and SHA-512
- Key stretching: Argon2
- OPAQUE implementation: `opaque-ke` 4.0.1, synchronized with RFC 9807

Your server must use the same suite.

## Install

After `Artifacts/COpaque.xcframework` is built, add this repository as a Swift Package dependency:

```swift
.package(
    url: "https://github.com/lukasa1993/opaque-swift.git",
    branch: "main"
)
```

Then depend on the `OpaqueSwift` product.

The GitHub Actions workflow builds the Rust static library for iOS device, iOS simulator, and macOS, creates `COpaque.xcframework`, runs the Swift tests, and commits the generated XCFramework to the repository.

## Registration

Registration has three wire messages. The username is application data. Send it beside the OPAQUE request so the server can use it as its credential identifier.

```swift
import OpaqueSwift

let username = "alice"
let registration = try OpaqueClient.startRegistration(password: "correct horse battery staple")

// Send username + registration.request to the server.
let registrationResponse: Data = receiveFromServer()

let result = try registration.finish(response: registrationResponse)

// Send result.upload to the server.
sendToServer(result.upload)

// Save this value. You need it to authenticate the same server during login.
let pinnedServerPublicKey = result.serverPublicKey
```

**Registration is special.** OPAQUE does not make an unauthenticated first registration safe by itself. Protect registration with a trusted device certificate, QR-code key fingerprint, authenticated setup secret, or another authenticated confidential channel. Also protect `result.upload`; the upstream library describes the registration upload as sensitive.

## Login

```swift
let login = try OpaqueClient.startLogin(password: "correct horse battery staple")

// Send username + login.request to the server.
let credentialResponse: Data = receiveFromServer()

let result = try login.finish(
    response: credentialResponse,
    expectedServerPublicKey: pinnedServerPublicKey
)

// Send KE3/finalization to the server.
sendToServer(result.finalization)

// After the server accepts finalization, both sides have the same session key.
let sessionKey = result.sessionKey
```

The server-key argument is required on purpose. `opaque-ke` exposes the static server public key at registration and login so applications can check server consistency. This package makes that check hard to forget.

## BLE mapping

A small GATT protocol can use these message types:

```text
REGISTER_START   -> registration.request
REGISTER_REPLY   <- RegistrationResponse
REGISTER_FINISH  -> registration.upload

LOGIN_START      -> login.request
LOGIN_REPLY      <- CredentialResponse
LOGIN_FINISH     -> login.finalization
```

BLE pairing and bonding are not required by this package. OPAQUE authenticates the password login and derives a session key. Your application can use that key with an AEAD protocol for later application messages.

## Secret handling

The session objects keep the password and serialized OPAQUE state only until `finish`. They overwrite their local `Data` buffers on finish and deinitialization as a best-effort cleanup. Swift and Foundation can make copies, so this is not a hard memory-zeroization guarantee. Prefer the `Data` password API when you need control over password storage; the `String` overload is a convenience API.

## Build locally

You need Xcode command-line tools and Rust 1.85 or later.

```bash
./scripts/build-xcframework.sh
swift test
```

## Current scope

This first package is client-only. A Rust server or embedded device can use `opaque-ke` 4.0.1 directly. The wire values produced here are the library's RFC 9807 serialized messages.

The wrapper does not currently declare its own project license. The upstream `opaque-ke` dependency is dual-licensed MIT or Apache-2.0.
