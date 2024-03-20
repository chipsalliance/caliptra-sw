# **General Integration Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Check for any RUST panics added to the code | **test_panic_missing** | N/A

<br><br>
# **Boot Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Boots Caliptra from ROM -> FMC -> Runtime | **test_standard** | N/A
Updates Caliptra with a new firmware image and tests that runtime boots | **test_update** | N/A
Boots runtime using the Caliptra runtime test binary | **test_boot** | N/A
Boots Caliptra and validates the firmware version | **test_fw_version** | N/A
Tests the persistent data layout on a RISC-V CPU with the runtime flag enabled| **test_persistent_data** | N/A
Checks that DPE contains the correct measurements upon booting runtime | **test_boot_tci_data** | N/A 
Checks that measurements in the measurement log are added to DPE upon booting runtime | **test_measurement_in_measurement_log_added_to_dpe** | N/A

<br><br>
# **Certificate Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the get_idev_cert mailbox command succeeds and verifies the size of the resulting certificate | **test_idev_id_cert** | N/A
Checks that the get_idev_cert mailbox command fails if the tbs_size is greater than the maximum allowed size | **test_idev_id_cert_size_too_big** | RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE
Validates the LDevId cert by checking that it is signed by the IDevId public key and verifies that it is a valid X.509 | **test_ldev_cert** | N/A
Validates the FMC alias cert by checking that it is signed by the LDevId public key and verifies that it is a valid X.509 | **test_fmc_alias_cert** | N/A
Validates the RT alias cert by checking that it is signed by the FMC alias public key and verifies that it is a valid X.509 | **test_rt_alias_cert** | N/A
Validates the DPE leaf cert by checking that it is signed by the RT alias public key and verifies that it is a valid X.509 | **test_dpe_leaf_cert** | N/A
Validates the full certificate chain | **test_full_cert_chain** | N/A
Checks if the owner and vendor cert validity dates are present in RT Alias cert | **test_rt_cert_with_custom_dates** | N/A

<br><br>
# **Disable Attestation Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the disable_attestation mailbox command succeeds and that attestation gets disabled | **test_disable_attestation_cmd** | N/A
Calls the disable_attestation mailbox command, triggers an update reset, and checks that attestation is still disabled | **test_attestation_disabled_flag_after_update_reset** | N/A

<br><br>
# **Stash Measurement Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the stash_measurement mailbox command succeeds and that measurements are added to DPE | **test_stash_measurement** | N/A
Test that PCR31 is extended with the measurement upon calling stash_measurement | **test_pcr31_extended_upon_stash_measurement** | N/A

<br><br>
# **Mailbox Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Check that the error register is cleared when a successful mailbox command runs after a failed mailbox command | **test_error_cleared** | RUNTIME_MAILBOX_INVALID_PARAMS
Checks that executing unimplemented mailbox commands fails | **test_unimplemented_cmds** | RUNTIME_UNIMPLEMENTED_COMMAND

<br><br>
# **Cryptography Verification Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Tests some common ECDSA problems | **ecdsa_cmd_run_wycheproof** | N/A
Streams a test message to a hashing accelerator and calls the ecdsa_verify mailbox command to verify the test signature | **test_ecdsa_verify_cmd** | N/A
Checks that the ecdsa_verify mailbox command fails if provided an invalid checksum | **test_ecdsa_verify_bad_chksum** | RUNTIME_INVALID_CHECKSUM
Streams 2 different test messages to the SHA accelerator and calls the lms_signature_verify mailbox command to verify several test signatures for each message | **test_lms_verify_cmd** | N/A
Checks that the lms_signature_verify mailbox command correctly returns an error for an invalid LMS signature | **test_lms_verify_failure** | RUNTIME_LMS_VERIFY_FAILED
Checks that the correct error is returned when an unsupported LMS algorithm type is provided in the signature to the lms_signature_verify mailbox command | **test_lms_verify_invalid_sig_lms_type** | RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM
Checks that the correct error is returned when an unsupported LMS algorithm type is provided in the public key to the lms_signature_verify mailbox command | **test_lms_verify_invalid_key_lms_type** | RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM
Checks that the correct error is returned when an unsupported LMS OTS algorithm type is provided to the lms_signature_verify mailbox command | **test_lms_verify_invalid_lmots_type** | RUNTIME_LMS_VERIFY_INVALID_LMOTS_ALGORITHM



<br><br>
# **Populate IDev Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Calls the POPULATE_IDEV_CERT mailbox command and checks that the IDevId certificate is able to be parsed from the certificate chain | **test_populate_idev_cert_cmd** | N/A
Checks that the populate_idev_cert mailbox command fails if the cert_size is greater than the maximum allowed size | **test_populate_idev_cert_size_too_big** | RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE

<br><br>
# **FIPS Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the version mailbox command succeeds and validates the FIPS version response | **test_fips_version** | N/A
Tests that the shutdown mailbox command succeeds and checks that executing mailbox commands after shutdown fails | **test_fips_shutdown** | RUNTIME_SHUTDOWN

<br><br>
# **Info Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the fw_info mailbox command succeeds and validates the response | **test_fw_info** | N/A
Checks that the get_idev_info mailbox command succeeds | **test_idev_id_info** | N/A
Checks that the capabilities mailbox command succeeds | **test_capabilities** | N/A

<br><br>
# **Certify Key Extended Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that validation of the DMTF otherName fails if it is badly formed | **test_dmtf_other_name_validation_fail** | RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED
Provides the DMTF otherName via the add_subject_alt_name mailbox command and verifies that the otherName is present in the DPE leaf cert | **test_dmtf_other_name_extension_present** | N/A
Checks that the DMTF otherName is not present in the DPE leaf cert if it is not provided by add_subject_alt_name or if it is not requested in the input flags | **test_dmtf_other_name_extension_not_present** | N/A

<br><br>
# **DPE Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the invoke_dpe mailbox command fails if the data_size is greater than the maximum allowed size | **test_invoke_dpe_size_too_big** | RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE
Calls the DPE command get_profile via the invoke_dpe mailbox command and verifies the DPE profile | **test_invoke_dpe_get_profile_cmd** | N/A
Calls the DPE command get_certificate_chain via the invoke_dpe mailbox command and verifies the size of the certificate chain |**test_invoke_dpe_get_certificate_chain_cmd** | N/A
Calls the DPE commands sign and certify_key via the invoke_dpe mailbox command and verifies the signature resulting from the sign command with the public key resulting from the certify_key command | **test_invoke_dpe_sign_and_certify_key_cmds** | N/A
Calls the DPE command sign with the symmetric flag set via the invoke_dpe mailbox command and checks that the resulting HMAC value is non-zero | **test_invoke_dpe_symmetric_sign** | N/A
Tests that failed DPE command populates mbox header with correct error code | **test_dpe_header_error_code** | N/A
Calls the DPE command certify_key with the CSR format via the invoke_dpe mailbox command and validates the fields of the CSR | **test_invoke_dpe_certify_key_csr** | N/A
Calls the DPE command rotate_context via the invoke_dpe mailbox command and verifies the rotated context handle | **test_invoke_dpe_rotate_context** | N/A

<br><br>
# **PAUSER Privilege Level Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks the limit on the number of active DPE contexts belonging to PL0 by calling derive_context via the invoke_dpe mailbox command with the RETAINS_PARENT flag set | **test_pl0_derive_context_dpe_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL1 by calling derive_context via the invoke_dpe mailbox command with the RETAINS_PARENT flag set | **test_pl1_derive_context_dpe_context_thresholds** | RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL0 by calling initialize_context via the invoke_dpe mailbox command with the SIMULATION flag set | **test_pl0_init_ctx_dpe_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL1 by calling initialize_context via the invoke_dpe mailbox command with the SIMULATION flag set | **test_pl1_init_ctx_dpe_context_thresholds** | RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks that PopulateIdevIdCert cannot be called from PL1 | **test_populate_idev_cannot_be_called_from_pl1** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks that CertifyKeyExtended cannot be called from PL1 | **test_certify_key_extended_cannot_be_called_from_pl1** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks that InvokeDpe::DeriveContext cannot be called from PL1 if it attempts to change locality to P0 | **test_derive_context_cannot_be_called_from_pl1_if_changes_locality_to_pl0** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks that InvokeDpe::CertifyKey cannot be called from PL1 if it requests X509 | **test_certify_key_x509_cannot_be_called_from_pl1** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks the limit on the number of active DPE contexts belonging to PL0 by calling the stash_measurement mailbox command | **test_stash_measurement_pl_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL0 by adding measurements to the measurement log | **test_measurement_log_pl_context_threshold** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED

<br><br>
# **PCR Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Increments the PCR reset counter, calls the quote_pcr mailbox command, and verifies the response | **test_pcr_quote** | N/A
Calls the extend_pcr mailbox command on various PCRs and checks that the PCR values are updated correctly | **test_extend_pcr_cmd_multiple_extensions** | N/A
Checks that extending an invalid PCR index throws an error | **test_extend_pcr_cmd_invalid_pcr_index** | RUNTIME_PCR_INVALID_INDEX
Checks that extending a reserved PCR throws an error | **test_extend_pcr_cmd_reserved_range** | RUNTIME_PCR_RESERVED

<br><br>
# **Tagging Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the dpe_tag_tci and dpe_get_tagged_tci mailbox commands succeed on a default context | **test_tagging_default_context** | N/A
Attempts to tag an already tagged context and verifies that it fails | **test_tagging_a_tagged_context** | RUNTIME_CONTEXT_ALREADY_TAGGED
Attempts to add a duplicate tag and verifies that it fails | **test_duplicate_tag** | RUNTIME_DUPLICATE_TAG
Calls the dpe_get_tagged_tci mailbox command with a tag that does not exist and checks that it fails | **test_get_tagged_tci_on_non_existent_tag** | RUNTIME_TAGGING_FAILURE
Attempts to tag an inactive context and verifies that it fails | **test_tagging_inactive_context** | RUNTIME_TAGGING_FAILURE
Tags the default context, destroys the default context, and checks that the dpe_get_tagged_tci mailbox command fails on the default context | **test_tagging_destroyed_context** | RUNTIME_TAGGING_FAILURE
Tags the default context, retires the default context, and checks that the dpe_get_tagged_tci mailbox command fails on the default context | **test_tagging_retired_context** | RUNTIME_TAGGING_FAILURE

<br><br>
# **Update Reset Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the DPE root measurement is set to the RT_FW_JOURNEY_PCR upon update reset | **test_rt_journey_pcr_updated_in_dpe** | N/A
Checks that context tags are persisted across update resets | **test_tags_persistence** | N/A
Corrupts the context tags and checks that an error is thrown upon update reset | **test_context_tags_validation** | RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED
Corrupts the shape of the DPE context tree and checks that an error is thrown upon update reset | **test_dpe_validation_deformed_structure** | RUNTIME_DPE_VALIDATION_FAILED
Corrupts DPE state and checks that an error is thrown upon update reset | **test_dpe_validation_illegal_state** | RUNTIME_DPE_VALIDATION_FAILED
Corrupts DPE by adding contexts past the threshold and checks that an error is thrown upon update reset | **test_dpe_validation_used_context_threshold_exceeded** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks that the pcr reset counter is persisted across update resets | **test_pcr_reset_counter_persistence** | N/A

<br><br>
# **Warm Reset Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Corrupts the DPE root measurement, triggers a warm reset, and checks that RT journey PCR validation fails | **test_rt_journey_pcr_validation** | RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED
Tests that there is a non-fatal error if runtime is executing a mailbox command during warm reset | **test_mbox_busy_during_warm_reset** | RUNTIME_CMD_BUSY_DURING_WARM_RESET

<br><br>
# **DPE Verification Tests**
These tests are implemented in Go and test end-to-end DPE attestation behavior. The DPE commands are called via a transport.
Test Scenario | Test Name | DPE Error Code
---|---|---
Calls and tests behavior of the DPE command InitializeContext | **TestInitializeContext** | N/A
Calls and tests behavior of the DPE command InitializeContext with simulation contexts | **TestInitializeSimulation** | N/A
Calls the DPE command CertifyKey, verifies the structure of the resulting certificate by parsing and linting it, and checks that the desired extensions are present | **TestCertifyKey** | N/A
Calls the DPE command CertifyKey with a simulation context handle, verifies the structure of the resulting certificate by parsing and linting it, and checks that the desired extensions are present | **TestCertifyKeySimulation** | N/A
Calls the DPE command GetCertificateChain and verifies the structure of each certificate in the chain by parsing and linting them | **TestGetCertificateChain** | N/A
Calls the DPE command GetProfile and verifies the DPE profile | **TestGetProfile** | N/A
Checks whether an error is reported when non-existent handle is passed as input to DPE commands | **TestInvalidHandle** | StatusInvalidHandle
Checks whether an error is reported when caller from one locality issues DPE commands in another locality | **TestWrongLocality** | StatusInvalidLocality
Checks whether an error is reported when using commands that are not supported in the DPE instance | **TestUnsupportedCommand** | StatusInvalidCommand
Checks whether an error is reported when enabling command flags that are not supported in the DPE instance | **TestUnsupportedCommandFlag** | StatusArgumentNotSupported
Calls and tests behavior of the DPE command RotateContext | **TestRotateContextHandle* | N/A
Calls and tests behavior of the DPE command RotateContext with simulation contexts | **TestRotateContextHandleSimulation* | N/A
Check whether the digital signature returned by Sign command can be verified using public key in signing key certificate returned by CertifyKey command | **TestAsymmetricSigning** | N/A
Check that the Sign command fails on simulated contexts as simulation context do not allow signing | **TestSignSimulation** | StatusInvalidArgument
Calls and tests behavior of the DPE command Sign with the Symmetric flag set | **TestSignSymmetric** | N/A
Tests using DPE to satisfy TPM PolicySigned | **TestTpmPolicySigning** | N/A
Calls and tests behavior of the DPE command DeriveContext | **TestDeriveContext** | N/A
Calls and tests behavior of the DPE command DeriveContext with the simulation flag | **TestDeriveContextSimulation** | N/A
Checks whether the number of derived contexts is limited by MAX_TCI_NODES attribute of the profile | **TestMaxTCIs** | StatusMaxTcis
Calls and tests behavior of the DPE command DeriveContext with the changes_locality flag | **TestChangeLocality** | N/A
Tests that commands trying to use features that are unsupported by child context fail | **TestPrivilegesEscalation** | StatusInvalidArgument
Calls and tests behavior of the DPE command DeriveContext with the internal_input_info and internal_input_dice flags | **TestInternalInputFlags** | N/A
Calls and tests behavior of the DPE command DeriveContext with the recursive flag | **TestDeriveContextRecursive** | N/A
Calls and tests behavior of the DPE command DeriveContext with the recursive flag on derived contexts | **TestDeriveContextRecursiveOnDerivedContexts** | N/A

<br><br>
# **Stress Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Run impactless update repeatedly for 500 times | **test_stress_update** | N/A

<br><br>
# **Test Gaps**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Add higher fidelity HMAC test that verifies correctness of HMAC tag based on UDS | N/A | N/A
Triggers a CPU fault and checks that extended error info is populated correctly | N/A | RUNTIME_GLOBAL_EXCEPTION
