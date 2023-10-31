# FIPS Functional Test Suite

## Purpose

FIPS Functional Test Suite is a collection of tests to exercise and verify FIPS related functions on Caliptra

The testing suite interfaces with Caliptra as an SoC would using the external, SoC-facing registers.

## Execution

cargo test --test fips_test_suite

## Test Environment Limitations

| Feature/Limitation Name  | Description                                                                         |
| :----------------------- | :---------------------------------------------------------------------------------- |
| test_env_immutable_rom   | Indicates the ROM is not modifiable in the environment (such as a Si platform)

Certain tests may require control that is not possible in all environments. Ideally these exceptions will be very limited, but they may still arise. Tracking these limitations is handled as rust features. Individual tests can be marked as incompatible with certain limitations and will be skipped if that limitation (rust feature) is enabled. If possible, checks should also be added to enforce these limitations in the FIPS test suite common code. See existing examples for test_env_immutable_rom.

These can be enabled using the --features argument for rust like: 
    cargo test --test fips_test_suite --features=test_env_immutable_rom

## Additional Environments

Support for additional environments can be done by creating new implementations/interfaces for the HW model at hw-model/src. See model_fpga_realtime.rs as an example. This implementation needs to be able to access the APB bus, control the input signals to caliptra, and, if possible, control ROM.