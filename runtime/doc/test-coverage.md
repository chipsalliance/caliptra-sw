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

<br><br>
# **Certificate Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the get_idev_cert mailbox command succeeds and verifies the size of the resulting certificate | **test_idev_id_cert** | N/A
Checks that the get_idev_cert mailbox command fails if the tbs_size is greater than the maximum allowed size | **test_idev_id_cert_size_too_big** | RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE
Validates the LDevId cert by checking that it is signed by the IDevId public key and verifies that it is a valid X.509 | **test_ldev_cert** | N/A
Validates the FMC alias cert by checking that it is signed by the LDevId public key and verifies that it is a valid X.509 | **test_fmc_alias_cert** | N/A
Validates the RT alias cert by checking that it is signed by the FMC alias public key and verifies that it is a valid X.509 | **test_rt_alias_cert** | N/A
Validates the full certificate chain | **test_full_cert_chain** | N/A
Checks if the owner and vendor cert validity dates are present in RT Alias cert | **test_rt_cert_with_custom_dates** | N/A

<br><br>
# **Disable Attestation Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the disable_attestation mailbox command succeeds | **test_disable_attestation_cmd** | N/A

<br><br>
# **Stash Measurement Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the stash_measurement mailbox command succeeds | **test_stash_measurement** | N/A

<br><br>
# **Mailbox Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Check that the error register is cleared when a successful mailbox command runs after a failed mailbox command | **test_error_cleared** | RUNTIME_MAILBOX_INVALID_PARAMS
Checks that the unimplemented mailbox command capabilities fails | **test_unimplemented_cmds** | RUNTIME_UNIMPLEMENTED_COMMAND

<br><br>
# **Cryptography Verification Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Tests some common ECDSA problems | **ecdsa_cmd_run_wycheproof** | N/A
Tests some common HMAC problems | **hmac_cmd_run_wycheproof** | N/A
Streams a test message to a hashing accelerator and calls the ecdsa_verify mailbox command to verify the test signature | **test_ecdsa_verify_cmd** | N/A
Calls the hmac_verify mailbox command to verify a NIST HMAC-SHA384 test vector | **test_hmac_verify_cmd** | N/A
Checks that the ecdsa_verify mailbox command fails if provided an invalid checksum | **test_ecdsa_verify_bad_chksum** | RUNTIME_INVALID_CHECKSUM
Checks that the pcr extension for multiple data sets works as expected | **test_extend_pcr_cmd_multiple_extensions** | N/A
Checks that accessing an invalid index is caught | **test_extend_pcr_cmd_invalid_pcr_index** | RUNTIME_PCR_INVALID_INDEX
Checks that accessing reserved indices is caught | **test_extend_pcr_cmd_reserved_range** | RUNTIME_PCR_RESERVED

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

<br><br>
# **PAUSER Privilege Level Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks the limit on the number of active DPE contexts belonging to PL0 by calling derive_child via the invoke_dpe mailbox command with the RETAINS_PARENT flag set | **test_pl0_derive_child_dpe_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL1 by calling derive_child via the invoke_dpe mailbox command with the RETAINS_PARENT flag set | **test_pl1_derive_child_dpe_context_thresholds** | RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL0 by calling initialize_context via the invoke_dpe mailbox command with the SIMULATION flag set | **test_pl0_init_ctx_dpe_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL1 by calling initialize_context via the invoke_dpe mailbox command with the SIMULATION flag set | **test_pl1_init_ctx_dpe_context_thresholds** | RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks that PopulateIdevIdCert cannot be called from PL1 | **test_populate_idev_cannot_be_called_from_pl1** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks that InvokeDpe::DeriveChild cannot be called from PL1 if it attempts to change locality to P0 | **test_derive_child_cannot_be_called_from_pl1_if_changes_locality_to_pl0** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks that InvokeDpe::CertifyKey cannot be called from PL1 if it requests X509 | **test_certify_key_x509_cannot_be_called_from_pl1** | RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
Checks the limit on the number of active DPE contexts belonging to PL0 by calling the stash_measurement mailbox command | **test_stash_measurement_pl_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Checks the limit on the number of active DPE contexts belonging to PL0 by adding measurements to the measurement log | **test_measurement_log_pl_context_threshold** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED

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
# **DPE Verification Tests**
These tests are implemented in Go and test end-to-end DPE attestation behavior. The DPE commands are called via a transport.
Test Scenario | Test Name | Go Error Code
---|---|---
Calls and tests behavior of the DPE command InitializeContext | **TestInitializeContext** | N/A
Calls and tests behavior of the DPE command InitializeContext with simulation contexts | **TestInitializeSimulation** | N/A
Calls the DPE command CertifyKey, verifies the structure of the resulting certificate by parsing and linting it, and checks that the desired extensions are present | **TestCertifyKey** | N/A
Calls the DPE command CertifyKey with a simulation context handle, verifies the structure of the resulting certificate by parsing and linting it, and checks that the desired extensions are present | **TestCertifyKeySimulation** | N/A
Calls the DPE command GetCertificateChain and verifies the structure of each certificate in the chain by parsing and linting them | **TestGetCertificateChain** | N/A
Calls the DPE command ExtendTci and verifies the resulting TCI | **TestExtendTCI** | N/A
Calls the DPE command ExtendTci with a derived child context and verifies the resulting TCI | **TestExtendTciOnDerivedContexts** | N/A
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

<br><br>
# **Stress Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Run impactless update repeatedly for 500 times | **test_stress_update** | N/A

<br><br>
# **Test Gaps**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Test DPE structure validation upon update reset | N/A | N/A
Trigger warm reset and check that DPE structure is valid upon RT initialization | N/A | N/A
Verify the RT Journey PCR on a warm reset | N/A | N/A
Check that the RT Journey PCR was updated correctly on update reset | N/A | N/A
Check that attestation is disabled if mbox_busy during a warm reset | N/A | N/A
Check that measurements in the measurement log are added to DPE upon initializing drivers | N/A | N/A
Check that PCR31 is updated in StashMeasurement | N/A | N/A
Test GetIdevCert cmd fails if provided bad signature or tbs | N/A | N/A
Add higher fidelity HMAC test that verifies correctness of HMAC tag based on UDS | N/A | N/A
Check that measurements are stored in DPE when StashMeasurement is called | N/A | N/A
Verify that DPE attestation flow fails after DisableAttestation is called | N/A | N/A
Check that mailbox valid pausers are measured into DPE upon RT startup | N/A | N/A
Check that the RT alias key is different from the key signing DPE certs | N/A | N/A
Test context tag validity upon warm/update reset | N/A | N/A