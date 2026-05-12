# Caliptra Xtask FPGA Flow

The `xtask` tool provides a streamlined flow for developing and testing Caliptra firmware on FPGA hardware. It automates firmware building, test cross-compilation, bitstream programming, and test execution.

## Commands

### `bootstrap`
Sets up the FPGA environment. This should be run after the FPGA board is powered on.
- Clones the `caliptra-sw` repository on the FPGA.
- Downloads and programs the appropriate bitstream.
- Configures the FPGA mode (e.g., `core` or `core-on-subsystem`). Defaults to `core`.

```bash
# Defaults to --configuration core
cargo xtask fpga bootstrap --target-host <ssh-host>
```

### `build`
Builds Caliptra firmware and (optionally) MCU firmware, then copies them to the FPGA.
- `--mcu-rev`: Specifies the git revision of `caliptra-mcu-sw` to build for subsystem modes.

```bash
cargo xtask fpga build --target-host <ssh-host>
```

### `build-test`
Cross-compiles test binaries for the FPGA architecture (`aarch64`) using a containerized build environment and copies the resulting archive to the FPGA.
- `--package-filter`: Optional `cargo-nextest` filter to reduce the number of compiled tests.

```bash
cargo xtask fpga build-test --target-host <ssh-host> --package-filter "package(caliptra-drivers)"
```

### `test`
Executes the test suite on the FPGA via SSH. 
- Automatically runs the `nextest` profile associated with the current configuration (e.g., `fpga-core` or `fpga-subsystem`).
- `--test-filter`: Optional filter for specific tests. **Note**: You should typically include a `package()` filter along with the `test()` filter to correctly target tests.
- `--test-output`: Enables real-time test output capture.

```bash
cargo xtask fpga test --target-host <ssh-host> --test-filter "package(caliptra-drivers) & test(test_persistent)"
```

## The "Magic" `caliptra-fpga` Target

All FPGA commands default to `--target-host caliptra-fpga`. To use this "magic" target without typing the full IP address or hostname every time, add an alias to your local `~/.ssh/config` file:

```text
Host caliptra-fpga
    HostName <IP_ADDRESS_OF_YOUR_FPGA>
    User runner
    # Optional: IdentityFile ~/.ssh/id_rsa
```

Once configured, you can omit the `--target-host` argument:

```bash
cargo xtask fpga test --test-filter "test(smoke)"
```

## Typical Workflow

1. **One-time Setup**: Configure your `~/.ssh/config` as shown above.
2. **Bootstrap**: `cargo xtask fpga bootstrap` (Run once per power cycle).
3. **Develop & Test**:
   - `cargo xtask fpga build`
   - `cargo xtask fpga build-test`
   - `cargo xtask fpga test`
