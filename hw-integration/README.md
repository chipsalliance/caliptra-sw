# SoC manager integration tests

All SoC manager integrations need to test base functionality to make sure everything is connected correctly in their implementation. This tool can be used to test base functionality.

## Tests

### Firmware load

This is a happy path test to ensures several portions of the boot integrity system are connected correctly, including:

- public key hash fuses
- Initial minimum SVN fuses (both are set to 1)
- Security state (including lifecycle and debug-locked)

This can be run with the example with the following command:

```bash
cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle target/debug/image_bundle.bin \
  --config-path hw-integration/test-configurations/default_test_config.toml
```

### FMC SVN too low

The only difference from the [Firmware load](#firmware-load) is the FMC SVN fuse value is incremented from 1 to 2. The actual fuse value is set to 3, but the ROM reads it as a masked value by checking the most significant bit. Setting the fuses to 2 or 3 is considered the same for the ROM.

The test checks for the `IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE` error.

Run the following command to test with the Caliptra simulator example:

```bash
cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle target/debug/image_bundle.bin \
  --config-path hw-integration/test-configurations/fmc_svn_too_low_test_config.toml
```

### Runtime SVN too low

The only difference from the [Firmware load](#firmware-load) is the runtime SVN fuse value is incremented from 1 to 2. The actual fuse value is set to 3, but the ROM reads it as a masked value by checking the most significant bit. Setting the fuses to 2 or 3 is considered the same for the ROM.

The test checks for the `IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE` error.

Run the following command to test with the Caliptra simulator example:

```bash
cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle target/debug/image_bundle.bin \
  --config-path hw-integration/test-configurations/rt_svn_too_low_test_config.toml
```

### ECDSA key revoked

The only difference from the [Firmware load](#firmware-load) is in the test configuration file. The fuses are altered to revoke the first ECDSA key. The test will then check for the `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED` error.

Run the following command to test with the Caliptra simulator example:

```bash
cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle target/debug/image_bundle.bin \
  --config-path hw-integration/test-configurations/ecc_key_revoked_test_config.toml
```

### LMS key revoked

The only difference from the [Firmware load](#firmware-load) is in the test configuration file. The fuses are altered to revoke the first LMS key. The test will then check for the `IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED` error.

Run the following command to test with the Caliptra simulator example:

```bash
cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle target/debug/image_bundle.bin \
  --config-path hw-integration/test-configurations/lms_key_revoked_test_config.toml
```

### Different IDevID with debug enabled

When debug is enabled on the SoC manager, it is required to put Caliptra in a debug unlocked state. When in debug unlocked, the device secrets are zeroized resulting in a different device identity. This test checks the IDevID changes when debug is enabled.

Run the following commands to test with the Caliptra simulator example:

```bash
keys=hw-integration/test-runner-lib/example/keys.toml
image_bundle=target/debug/image_bundle.bin

cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle $image_bundle \
  --expected-keys-path $keys \
  --config-path hw-integration/test-configurations/default_test_config.toml

cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle $image_bundle \
  --expected-keys-path $keys \
  --config-path hw-integration/test-configurations/idev_test_debug_locked.toml
```

### Different DevIDs with combos of UDS and field entropy

This test checks the the device identity changes when different combinations of UDS and field entropy are used. This is done by setting the UDS and field entropy to different values and checking the DevID public keys. The test configuration files are altered to set the UDS and field entropy to different values.

Run the following commands to test with the Caliptra simulator example:

```bash
keys=hw-integration/test-runner-lib/example/keys.toml
image_bundle=target/debug/image_bundle.bin

cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle $image_bundle \
  --expected-keys-path $keys \
  --config-path hw-integration/test-configurations/default_test_config.toml

cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle $image_bundle \
  --expected-keys-path $keys \
  --config-path hw-integration/test-configurations/idev_test_uds_a_fe_a.toml

cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle $image_bundle \
  --expected-keys-path $keys \
  --config-path hw-integration/test-configurations/idev_test_uds_a_fe_b.toml

cargo run -p caliptra-hw-model-integration-test-runner -- \
  --image-bundle $image_bundle \
  --expected-keys-path $keys \
  --config-path hw-integration/test-configurations/idev_test_uds_b_fe_a.toml
```
