#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/Rust/Cargo.toml"
TARGET_DIR="$ROOT/Rust/target"
ARTIFACT_DIR="$ROOT/Artifacts"
XCFRAMEWORK="$ARTIFACT_DIR/COpaque.xcframework"
BUILD_DIR="$ROOT/.build/opaque-rust"
LIB_NAME="libopaque_swift_ffi.a"
SIM_DIR="$BUILD_DIR/ios-simulator"
MAC_DIR="$BUILD_DIR/macos"
SIM_LIB="$SIM_DIR/$LIB_NAME"
MAC_LIB="$MAC_DIR/$LIB_NAME"

TARGETS=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
  aarch64-apple-darwin
  x86_64-apple-darwin
)

rustup target add "${TARGETS[@]}"

for target in "${TARGETS[@]}"; do
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build \
    --manifest-path "$MANIFEST" \
    --release \
    --target "$target"
done

rm -rf "$BUILD_DIR" "$XCFRAMEWORK"
mkdir -p "$SIM_DIR" "$MAC_DIR" "$ARTIFACT_DIR"

lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-ios/release/$LIB_NAME" \
  -output "$SIM_LIB"

lipo -create \
  "$TARGET_DIR/aarch64-apple-darwin/release/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-darwin/release/$LIB_NAME" \
  -output "$MAC_LIB"

xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/$LIB_NAME" \
  -headers "$ROOT/Rust/include" \
  -library "$SIM_LIB" \
  -headers "$ROOT/Rust/include" \
  -library "$MAC_LIB" \
  -headers "$ROOT/Rust/include" \
  -output "$XCFRAMEWORK"

echo "Built $XCFRAMEWORK"
