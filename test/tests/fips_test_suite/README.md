# FIPS Functional Test Suite

## Purpose

FIPS Functional Test Suite is a collection of tests to exercise and verify FIPS related functions on Caliptra

The testing suite interfaces with Caliptra as an SoC would using the external, SoC-facing registers.

## Execution

cargo test --test fips_test_suite

## Options

| Option Name               | Description                                                                                            |
| :------------------------ | :----------------------------------------------------------------------------------------------------- |
| FIPS_TEST_ROM_BIN         | Path to the the ROM binary to use (only applies to tests that do not build their own ROM)
| FIPS_TEST_FW_BIN          | Path to the the FW image to use (only applies to tests that do not build their own FW)
| FIPS_TEST_HW_EXP_VERSION  | HW release version used to determine expected values (see test\tests\fips_test_suite\common.rs)
| FIPS_TEST_ROM_EXP_VERSION | ROM release version used to determine expected values (see test\tests\fips_test_suite\common.rs)
| FIPS_TEST_RT_EXP_VERSION  | Runtime release version used to determine expected values (see test\tests\fips_test_suite\common.rs)

Options are environment variables. One way to specify them at the command line when calling cargo test:
    OPTION_NAME=VALUE cargo test --test fips_test_suite

## Test Environment Limitations

| Feature/Limitation Name  | Description                                                                         |
| :----------------------- | :---------------------------------------------------------------------------------- |
| test_env_immutable_rom   | Indicates the ROM is not modifiable in the environment (such as a Si platform)

Certain tests may require control that is not possible in all environments. Ideally these exceptions will be very limited, but they may still arise. Tracking these limitations is handled as rust features. Individual tests can be marked as incompatible with certain limitations and will be skipped if that limitation (rust feature) is enabled. If possible, checks should also be added to enforce these limitations in the FIPS test suite common code. See existing examples for test_env_immutable_rom.

These can be enabled using the --features argument for rust like: 
    cargo test --test fips_test_suite --features=test_env_immutable_rom

## Additional Environments

Support for additional environments can be done by creating new implementations/interfaces for the HW model at hw-model/src. See model_fpga_realtime.rs as an example. This implementation needs to be able to access the APB bus, control the input signals to Caliptra, and, if possible, control ROM.

## Test Hooks

Certain tests require "hooks" into the ROM or FW to cause operation to deviate from the normal flow (ie. injecting errors or halting execution at specific points). This functionality is enabled using a build option called "fips-test-hooks". Then, the specific command codes are written and read from the DBG_MANUF_SERVICE_REG. The ROM/FW can respond back with a status code written to the same field if applicable. See command codes in drivers\src\fips_test_hooks.rs for more details.

Test hooks are needed to meet the following FIPS 140-3 test requirements:
    TE03.07.02
    TE03.07.04
    TE04.29.01
    TE10.07.03
    TE10.08.03
    TE10.09.03
    TE10.10.01
    TE10.10.02
    TE10.35.04
