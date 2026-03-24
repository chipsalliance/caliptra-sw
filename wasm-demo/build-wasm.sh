#!/bin/bash
# Build the Caliptra WASM emulator and set up the www/ directory for serving.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for wasm-pack
if ! command -v wasm-pack &>/dev/null; then
    echo "wasm-pack not found. Installing..."
    cargo install wasm-pack --locked
fi

# Check for wasm32 target
if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
    echo "Adding wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown
fi

echo "Building WASM (release)..."
wasm-pack build --target web --release

echo "Copying WASM output to www/..."
cp pkg/caliptra_wasm_demo_bg.wasm www/
cp pkg/caliptra_wasm_demo.js www/

# Copy default ROM if not already present
ROM_SRC="../rom/ci_frozen_rom/2.1/caliptra-rom-with-log-2.1.0-a72a76f.bin"
if [ -f "$ROM_SRC" ]; then
    cp "$ROM_SRC" www/default-rom.bin
    echo "Copied default ROM (with-log variant) to www/default-rom.bin"
else
    echo "WARNING: Default ROM not found at $ROM_SRC"
    echo "You will need to upload a ROM manually in the UI."
fi

echo ""
echo "Build complete! To run:"
echo "  cd $SCRIPT_DIR/www"
echo "  python3 -m http.server 8080"
echo "  Then open http://localhost:8080"
