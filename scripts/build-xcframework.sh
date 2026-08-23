#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/Rust/Cargo.toml"
TARGET_DIR="$ROOT/Rust/target"
ARTIFACT_DIR="$ROOT/Artifacts"
XCFRAMEWORK="$ARTIFACT_DIR/COpaque.xcframework"
BUILD_DIR="$ROOT/.build/opaque-rust"
LIB_NAME="libopaque_swift_ffi.a"

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
mkdir -p "$BUILD_DIR" "$ARTIFACT_DIR"

lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-ios/release/$LIB_NAME" \
  -output "$BUILD_DIR/$LIB_NAME-ios-simulator"

lipo -create \
  "$TARGET_DIR/aarch64-apple-darwin/release/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-darwin/release/$LIB_NAME" \
  -output "$BUILD_DIR/$LIB_NAME-macos"

xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/$LIB_NAME" \
  -headers "$ROOT/Rust/include" \
  -library "$BUILD_DIR/$LIB_NAME-ios-simulator" \
  -headers "$ROOT/Rust/include" \
  -library "$BUILD_DIR/$LIB_NAME-macos" \
  -headers "$ROOT/Rust/include" \
  -output "$XCFRAMEWORK"

echo "Built $XCFRAMEWORK"
