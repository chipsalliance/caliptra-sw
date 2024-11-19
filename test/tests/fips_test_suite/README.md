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

## Tests

| **Test Name** | **Test Cases** | **Flow** |
| --- | --- | --- |
| check_version_rom  <br>check_version_rt | TE02.19.02  <br>TE04.13.01  <br>TE04.14.02  <br>TE04.28.01 | Boot to rom or runtime  <br>Execute Version command  <br>Confirm all fields are expected values |
| execute_all_services_rom | TE02.24.02  <br>TE04.11.02 | Boot to rom  <br>Execute all commands checking:  <br>FIPS Approved field==1  <br>Output data matches what is expected (verify size of response?) |
| execute_all_services_rt | TE02.24.02  <br>TE04.11.02 | Boot to runtime, see above  <br>(Execute all runtime commands, including all DPE commands) |
| kat_halt_check_no_output | TE03.07.02  <br>TE03.07.04 | Halt the KATS in ROM during early boot  <br>Attempt output to verify it is inhibited |
| fw_load_halt_check_no_output | TE03.07.02  <br>TE04.29.01 | Enable hook to halt in FW load  <br>Start a fw load  <br>Attempt output to verify it is inhibited |
| zeroize_halt_check_no_output | TE03.07.02 | Enable hook to halt during zeroize in (runtime) shutdown command  <br>Issue shutdown command  <br>Attempt output to verify it is inhibited |
| input_error_check_no_output | TE03.07.02  <br>TE03.15.06 | Issue a command with incorrect input args  <br>Attempt output to verify it is inhibited |
| version_info_update | TE04.32.01 | Issue version command  <br>Save outputs  <br>Load FW  <br>Issue a version command  <br>Compare to previous version command to verify difference |
| corrupted_fw_load | TE05.05.07  <br>TE05.06.06  <br>TE05.08.01  <br>TE10.37.05  <br>TE10.37.06 | Corrupt a FW image by changing the binary data in runtime  <br>Execute a version command  <br>Store response  <br>Start a FW load  <br>Verify an error is reported  <br>Verify we cannot use the module by issuing another command  <br>Verify version info is unchanged - (must use reg instead of command here) |
| attempt_ssp_access_fw_load | TE06.05.03  <br>TE06.06.02 | Start a FW load  <br>Halt during load using test hook  <br>\- Prove JTAG is disabled outside of debug mode  <br>\- Attempt to read UDS and field entropy fuses  <br>\- Attempt to modify pub key hash fuse  <br>\- Attempt to access keyvault regs at same offset caliptra uses on the SoC side  <br>\- Attempt to access DCCM at same offset caliptra uses on the SoC side  <br>\- Prove we can't read mailbox output data |
| attempt_ssp_access_rom  <br>attempt_ssp_access_rt | TE09.01.02  <br>TE09.01.03 | Boot to ROM or runtime  <br>Perform checks from attempt_ssp_access_fw_load |
| fw_load_bad_vendor_ecc_pub_key  <br>fw_load_bad_owner_ecc_pub_key  <br>fw_load_bad_vendor_lms_pub_key  <br>fw_load_bad_owner_lms_pub_key | TE09.02.02 | Modify the public keys on the FW image  <br>Attempt to load the FW image  <br>Verify an error is returned |
| kat_sha1_digest_failure_rom  <br>kat_sha1_digest_mismatch_rom  <br>kat_sha256_digest_failure_rom  <br>kat_sha256_digest_mismatch_rom  <br>kat_sha384_digest_failure_rom  <br>kat_sha384_digest_mismatch_rom  <br>kat_sha2_512_384acc_digest_start_op_failure_rom  <br>kat_sha2_512_384acc_digest_failure_rom  <br>kat_sha2_512_384acc_digest_mismatch_rom  <br>kat_ecc384_signature_generate_failure_rom  <br>kat_ecc384_signature_verify_failure_rom  <br>kat_hmac384_failure_rom  <br>kat_hmac384_tag_mismatch_rom  <br>kat_lms_digest_mismatch_rom | TE10.07.03  <br>TE10.08.03  <br>TE10.09.03  <br>TE10.10.01  <br>TE10.10.02 | Enable the hook for triggering an error with the SHA1 KAT  <br>Verify the correct error is returned  <br>Verify we cannot utilize the associated functionality by proving we can't issues commands  <br>Verify an undocumented attempt to clear the error fails  <br>Clear the error with an approved method - restart Caliptra  <br>Verify crypto operations using the engine can be performed |
| kat_sha1_digest_failure_rt  <br>kat_sha1_digest_mismatch_rt  <br>kat_sha256_digest_failure_rt  <br>kat_sha256_digest_mismatch_rt  <br>kat_sha384_digest_failure_rt  <br>kat_sha384_digest_mismatch_rt  <br>kat_sha2_512_384acc_digest_start_op_failure_rt  <br>kat_sha2_512_384acc_digest_failure_rt  <br>kat_sha2_512_384acc_digest_mismatch_rt  <br>kat_ecc384_signature_generate_failure_rt  <br>kat_ecc384_signature_verify_failure_rt  <br>kat_hmac384_failure_rt  <br>kat_hmac384_tag_mismatch_rt  <br>kat_lms_digest_mismatch_rt | TE10.07.03  <br>TE10.08.03  <br>TE10.09.03  <br>TE10.10.01  <br>TE10.10.02 | Boot to runtime  <br>Enable the hook for triggering an error with the KAT  <br>Issue self test command  <br>Verify the correct error is returned  <br>Verify we cannot utilize the associated functionality by proving we can't issues commands  <br>Verify an undocumented attempt to clear the error fails  <br>Clear the error with an approved method - restart Caliptra  <br>Verify crypto operations using the engine can be performed |
| integrity_check_failure_rom | TE10.07.03  <br>TE10.08.03  <br>TE10.09.03  <br>TE10.10.01  <br>TE10.10.02 | Corrupt ROM integrity check hash  <br>Verify the correct error is returned  <br>Verify we cannot issue commands  <br>Verify an undocumented attempt to clear the error fails  <br>(Cannot clear this error without changing ROM which would invlove recreating the whole platform with a new ROM and therefore isn't really a continuation of this test) |
| fw_load_error_manifest_marker_mismatch  <br>fw_load_error_manifest_size_mismatch  <br>fw_load_error_vendor_pub_key_digest_invalid  <br>fw_load_error_vendor_pub_key_digest_failure  <br>fw_load_error_vendor_pub_key_digest_mismatch  <br>fw_load_error_owner_pub_key_digest_failure  <br>fw_load_error_owner_pub_key_digest_mismatch  <br>fw_load_error_vendor_ecc_pub_key_index_out_of_bounds  <br>fw_load_error_vendor_ecc_pub_key_revoked  <br>fw_load_error_header_digest_failure  <br>fw_load_error_vendor_ecc_verify_failure  <br>fw_load_error_vendor_ecc_signature_invalid  <br>fw_load_error_vendor_ecc_pub_key_index_mismatch  <br>fw_load_error_owner_ecc_verify_failure  <br>fw_load_error_owner_ecc_signature_invalid  <br>fw_load_error_toc_entry_count_invalid  <br>fw_load_error_toc_digest_failure  <br>fw_load_error_toc_digest_mismatch  <br>fw_load_error_fmc_digest_failure  <br>fw_load_error_fmc_digest_mismatch  <br>fw_load_error_runtime_digest_failure  <br>fw_load_error_runtime_digest_mismatch  <br>fw_load_error_fmc_runtime_overlap  <br>fw_load_error_fmc_runtime_incorrect_order  <br>fw_load_error_owner_ecc_pub_key_invalid_arg  <br>fw_load_error_owner_ecc_signature_invalid_arg  <br>fw_load_error_vendor_pub_key_digest_invalid_arg  <br>fw_load_error_vendor_ecc_signature_invalid_arg  <br>fw_load_error_update_reset_owner_digest_failure  <br>fw_load_error_update_reset_vendor_ecc_pub_key_idx_mismatch  <br>fw_load_error_update_reset_fmc_digest_mismatch  <br>fw_load_error_fmc_load_addr_invalid  <br>fw_load_error_fmc_load_addr_unaligned  <br>fw_load_error_fmc_entry_point_invalid  <br>fw_load_error_fmc_entry_point_unaligned  <br>fw_load_error_runtime_load_addr_invalid  <br>fw_load_error_runtime_load_addr_unaligned  <br>fw_load_error_runtime_entry_point_invalid  <br>fw_load_error_runtime_entry_point_unaligned  <br>fw_load_error_runtime_svn_greater_than_max_supported  <br>fw_load_error_runtime_svn_less_than_fuse  <br>fw_load_error_image_len_more_than_bundle_size  <br>fw_load_error_vendor_lms_pub_key_index_mismatch  <br>fw_load_error_vendor_lms_verify_failure  <br>fw_load_error_vendor_lms_pub_key_index_out_of_bounds  <br>fw_load_error_vendor_lms_signature_invalid  <br>fw_load_error_fmc_runtime_load_addr_overlap  <br>fw_load_error_owner_lms_verify_failure  <br>fw_load_error_owner_lms_signature_invalid  <br>fw_load_error_vendor_lms_pub_key_revoked  <br>fw_load_error_fmc_size_zero  <br>fw_load_error_runtime_size_zero  <br>fw_load_error_update_reset_vendor_lms_pub_key_idx_mismatch  <br>fw_load_error_fmc_load_address_image_size_arithmetic_overflow  <br>fw_load_error_runtime_load_address_image_size_arithmetic_overflow  <br>fw_load_error_toc_entry_range_arithmetic_overflow | TE10.07.03  <br>TE10.08.03  <br>TE10.09.03  <br>TE10.10.01  <br>TE10.10.02 | Make change related to error in fw bundle or fuses  <br>Attempt to load the FW  <br>Verify the correct error is returned  <br>Verify we cannot utilize RT FW by sending a message  <br>Verify an undocumented attempt to clear the error fails  <br>Clear the error with an approved method - restart Caliptra  <br>Verify we can utilize RT FW by sending a message  <br>NOTE: This isn't a specific crypto engine but this still counts as a self test, some of the requirements are tailored toward crypto engines. |
| key_pair_consistency_error | TE10.35.04 | Enable hook to corrupt key pair during generation  <br>Trigger the keypair generation (Just boot and allow DICE flow to start?)  <br>Verify the correct error for key pair inconsistency is generated |
| fw_load_blank_pub_keys  <br>fw_load_blank_pub_key_hashes | TE10.37.09 | Clear the public keys/hashes from the FW image  <br>Start the FW load  <br>Verify the correct error is returned |
| fips_self_test_rom  <br>fips_self_test_rt | TE10.53.02 | Execute FIPS self test command  <br>Verify the output is correct and the self tests pass |
| jtag_locked |     | Verfify JTAG access is prevented when in debug locked mode |