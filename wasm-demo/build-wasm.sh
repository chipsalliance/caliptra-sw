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

# Build default FW image bundle (uses fake/test keys)
echo "Building default FW image bundle..."
FW_TMP="$(mktemp)"
cd "$SCRIPT_DIR/.."
cargo run -p caliptra-builder -- --fw "$FW_TMP" 2>/dev/null
cp "$FW_TMP" "$SCRIPT_DIR/www/default-fw.bin"
echo "Built default FW bundle ($(wc -c < "$FW_TMP") bytes)"

# Extract PK hashes from the FW image
echo "Extracting PK hashes from FW image..."
cd "$SCRIPT_DIR/tools"
HASHES=$(cargo run --quiet -- "$FW_TMP" 2>/dev/null)
rm -f "$FW_TMP"

VENDOR_PK_HASH=$(echo "$HASHES" | grep VENDOR_PK_HASH | cut -d= -f2)
OWNER_PK_HASH=$(echo "$HASHES" | grep OWNER_PK_HASH | cut -d= -f2)
echo "  Vendor PK hash: $VENDOR_PK_HASH"
echo "  Owner PK hash:  $OWNER_PK_HASH"

# Write defaults JSON for the web UI
cat > "$SCRIPT_DIR/www/defaults.json" << JSONEOF
{
  "vendor_pk_hash": "$VENDOR_PK_HASH",
  "owner_pk_hash": "$OWNER_PK_HASH"
}
JSONEOF
echo "Wrote www/defaults.json"

echo ""
echo "Build complete! To run:"
echo "  cd $SCRIPT_DIR/www"
echo "  python3 -m http.server 8080"
echo "  Then open http://localhost:8080"
