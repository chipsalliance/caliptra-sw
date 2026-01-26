# OCP EAT Token Generator & Decoder

## Features

This binary provides both generation and decoding of OCP EAT (Entity Attestation Token) CBOR files.

### Generation Mode
- Automatically creates an `output/` folder and saves all generated CBOR tokens there
- Supports structured concise evidence with IETF CoRIM format
- Generates cryptographically signed tokens with X.509 certificates

### Decode Mode  
- Decodes existing CBOR tokens using the integrated Python decoder
- Performs signature validation and certificate analysis
- Displays detailed EAT claims analysis and CBOR structure breakdown

## Usage

### Generate Tokens
```bash
# Generate a token - automatically saved to output/my_token.cbor
cargo run --features std,crypto -- my_token.cbor

# View generated tokens
ls -la output/
```

### Decode Tokens
```bash
# Decode an existing token (works with or without crypto features)
cargo run --features std,crypto -- --decode output/my_token.cbor
cargo run --no-default-features --features std -- --decode output/my_token.cbor

# Decode tokens from any path
cargo run -- --decode /path/to/external_token.cbor
```

### Help
```bash
# Show usage help
cargo run --features std,crypto
cargo run -- --decode
```

## Directory Structure
```
runtime/userspace/api/eat/
├── src/                    # Rust source code
│   ├── main.rs            # Main binary with CLI (generation & decode modes)
│   ├── lib.rs             # Library implementation
│   ├── cbor.rs            # CBOR encoding utilities
│   ├── cose.rs            # COSE signature utilities
│   ├── claim_key.rs       # EAT claim key definitions
│   └── error.rs           # Error handling modules
│   └── ocp_profile/       # OCP profile-specific EAT claims encoding modules for attestation
│   └── csr_eat.rs         # Envelope Signed CSR EAT claims encoding module
├── decoder/               # Python decoder scripts
│   ├── decode.py          # Main decoder script
│   ├── signature_analysis.py
│   └── signature_validation.py
├── output/                # Auto-created output directory for tokens
│   └── *.cbor            # Generated CBOR token files
├── Cargo.toml            # Rust package manifest
└── OUTPUT_README.md      # This documentation
```

## Requirements

### For Token Generation
- **Rust Features**: Requires `std` and `crypto` features
- **Output folder**: Automatically created if it doesn't exist

### For Token Decoding
- **Rust Features**: Requires `std` feature
- **Python Environment**: Python 3.7+ with cryptography library

#### Python Virtual Environment Setup
```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate  # On Linux/macOS
# or
venv\Scripts\activate     # On Windows

# Install required dependencies
pip install cryptography cbor2 pycose

# Verify installation
python -c "import cryptography, cbor2, cose; print('All dependencies installed successfully')"
```

#### Using the Decoder
Once the virtual environment is set up and activated, the decode functionality will work automatically:
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Now decode tokens (the binary will use the activated Python environment)
cargo run --features std,crypto -- --decode output/my_token.cbor
```

#### Troubleshooting Python Dependencies
If you encounter import errors during decoding:
```bash
# Check if dependencies are installed
pip list | grep -E "(cryptography|cbor2|cose)"

# Install missing dependencies
pip install cryptography cbor2 pycose

# For development/debugging, you can run the decoder directly
cd decoder
python decode.py ../output/my_token.cbor
```
