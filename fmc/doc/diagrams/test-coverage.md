# Test Cases

## Code quality

| Name    | Description |
| -------- | ------- |
**test_panic_missing** | Checks for any RUST panics added to the code

## Boot flow

| Name    | Description |
| -------- | ------- |
| **test_pcr_log** | Check if PCR log entries are correctly logged to DCCM and PCRS are locked. |
| **test_boot_status_reporting** | Checks boot status codeis being reported correctly. |
| **test_fht_info** | Test FHT fields are valid |

## **Dice Tests**

| Name    | Description |
| -------- | ------- |
| test_rt_cert_with_custom_dates  | Check if the owner and vendor cert validty dates are present in RT Alias cert    |
| cert_tests | Test DICE Certificate Chain     |
