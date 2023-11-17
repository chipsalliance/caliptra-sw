# **General Integration Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Check for any RUST panics added to the code | **test_panic_missing** | N/A

<br><br>
# **Boot Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Boots Caliptra from ROM -> FMC -> Runtime | **test_standard** | N/A
Update Caliptra with a new firmware image and test that runtime boots | **test_update** | N/A
Boots runtime using the Caliptra runtime test binary | **test_boot** | N/A
Boots Caliptra and validates the firmware version | **test_fw_version** | N/A

<br><br>
# **Certificate Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Fully validates the LDevID, FMC, and RT X.509 certificates as well as the full certificate chain | **test_certs** | N/A
Check if the owner and vendor cert validity dates are present in RT Alias cert | **test_rt_cert_with_custom_dates** | N/A

<br><br>
# **DPE Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Calls the DPE command get_profile via the invoke_dpe mailbox command and verifies the DPE profile | **test_invoke_dpe_get_profile_cmd** | N/A
Calls the DPE command get_certificate_chain via the invoke_dpe mailbox command and verifies the size of the certificate chain |**test_invoke_dpe_get_certificate_chain_cmd** | N/A
Checks the limit on the number of active DPE contexts belonging to a pauser privilege level |  **test_pauser_privilege_level_dpe_context_thresholds** | RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED
Calls the DPE commands sign and certify_key via the invoke_dpe mailbox command and verifies the signature resulting from the sign command with the public key resulting from the certify_key command | **test_invoke_dpe_sign_and_certify_key_cmds** | N/A

<br><br>
# **DPE Verification Tests**
These tests are implemented in Go and test end-to-end DPE attestation behavior. The DPE commands are called via a transport.
Test Scenario | Test Name | Go Error Code
---|---|---
Calls and tests behavior of the DPE command InitializeContext | **TestInitializeContext** | N/A
Calls and tests behavior of the DPE command InitializeContext with simulation contexts | **TestInitializeContextSimulation** | N/A
Calls the DPE command CertifyKey, verifies the structure of the resulting certificate by parsing and linting it, and checks that the desired extensions are present | **TestCertifyKey** | N/A
Calls the DPE command CertifyKey with a simulation context handle, verifies the structure of the resulting certificate by parsing and linting it, and checks that the desired extensions are present | **TestCertifyKey_SimulationMode** | N/A
Calls the DPE command GetCertificateChain and verifies the structure of each certificate in the chain by parsing and linting them | **TestGetCertificateChain** | N/A
Calls and tests behavior of the DPE command TagTci | **TestTagTCI** | N/A
Calls the DPE command GetProfile and verifies the DPE profile | **TestGetProfile** | N/A
Checks whether an error is reported when non-existent handle is passed as input to DPE commands | **TestInvalidHandle** | StatusInvalidHandle
Checks whether an error is reported when caller from one locality issues DPE commands in another locality | **TestWrongLocality** | StatusInvalidLocality
Checks whether an error is reported when using commands that are not supported in the DPE instance | **TestUnsupportedCommand** | StatusInvalidCommand
Checks whether an error is reported when enabling command flags that are not supported in the DPE instance | **TestUnsupportedCommandFlag** | StatusArgumentNotSupported

<br><br>
# **Mailbox Command Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Checks that the fw_info mailbox command succeeds and validates the response | **test_fw_info** | N/A
Checks that the stash_measurement mailbox command succeeds | **test_stash_measurement** | N/A
Checks that the disable_attestation mailbox command succeeds | **test_disable_attestation_cmd** | N/A
Streams a test message to a hashing accelerator and calls the ecdsa_verify mailbox command to verify the test signature | **test_ecdsa_verify_cmd** | N/A
Checks that the unimplemented mailbox commands get_idev_csr and get_ldev_cert fail | **test_unimplemented_cmds** | RUNTIME_UNIMPLEMENTED_COMMAND
Checks that the get_idev_info mailbox command succeeds | **test_idev_id_info** | N/A
Checks that the get_idev_cert mailbox command succeeds and verifies the size of the resulting certificate | **test_idev_id_cert** | N/A
Checks that the version mailbox command succeeds and validates the FIPS version response | **test_fips_cmd_api** | RUNTIME_SHUTDOWN
Check that the error register is cleared when a successful mailbox command runs after a failed mailbox command | **test_error_cleared** | RUNTIME_MAILBOX_INVALID_PARAMS
Calls the POPULATE_IDEV_CERT mailbox command and checks that the IDevId certificate is able to be parsed from the certificate chain | **test_populate_idev_cert_cmd** | N/A

<br><br>
# **Wycheproof Tests**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Tests some common ECDSA problems | **ecdsa_cmd_run_wycheproof** | N/A
Tests some common HMAC problems | **hmac_cmd_run_wycheproof** | N/A

<br><br>
# **Test Gaps**
Test Scenario| Test Name | Runtime Error Code
---|---|---
Check validation of DPE structure after a warm/update reset and ensure that validation fails if the DPE's SRAM bytes are maliciously edited | N/A | N/A
Verify the RT Journey PCR on a warm reset | N/A | N/A
Check that the RT Journey PCR was updated correctly on update reset | N/A | N/A
Check if disable attestation was called when the mailbox is executing a command during a warm reset | N/A | N/A
Check that measurements in the measurement log are added to DPE upon initializing drivers | N/A | N/A