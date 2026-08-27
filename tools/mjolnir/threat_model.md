<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Caliptra Firmware Threat Model (Distilled)

This document provides a distilled, firmware-focused view of the threats identified in the comprehensive component-level threat model. It removes duplication across hundreds of components and focuses on the implications for firmware security, assumptions, and required mitigations.

## 1. Trust Boundaries & Assets

Firmware operates within the high-trust boundary of the Caliptra Root of Trust (RoT) core. However, it must interact with and protect against threats crossing several internal and external boundaries:

- **Core Execution Domain (Highest Trust):** The RISC-V core executing firmware.
- **Tightly Coupled Memories (High Trust):** ICCM (Instructions) and DCCM (Data).
- **Key Vault & Crypto Engines (High Trust):** Storage and processing of sensitive keys.
- **SoC Bus / Fabric (Untrusted/Semi-trusted):** The boundary where external masters (DMA, SoC CPU) interact with Caliptra.
- **Debug/Test Interfaces (Untrusted):** JTAG, Scan chains.

## 2. Key Threat Categories & Firmware Impact

### 2.1. Fault Injection (Tampering)

**Threat:** Attackers utilizing voltage, clock, or EM/laser glitching can disrupt hardware state machines, flip bits in registers or memory, and alter control flow.

- **Firmware Impact:**
  - **Control Flow Hijacking:** Glitches can skip instructions (e.g., signature checks, privilege checks) or alter branch decisions. Firmware must use defensive coding (e.g., redundant checks, double-signaling) for critical security decisions.
  - **Instruction Splicing/Mutation:** Corrupting instruction fetch or decompression can create synthetic instructions or alter privilege levels.
  - **ECC Bypass:** Glitching the ECC disable signal or suppressing error flags can allow execution or processing of corrupted data.

### 2.2. DMA & Bus Master Exploits (Spoofing & Tampering)

**Threat:** Malicious or compromised bus masters (e.g., external DMA engines) attempting to access protected resources.

- **Firmware Impact:**
  - **PMP/MPU Bypass:** Several analyses indicate that some DMA paths might bypass standard Physical Memory Protection (PMP) or Memory Protection Unit (MPU) checks. Firmware cannot assume PMP protects all memory from DMA. It must strictly configure and verify all bus master access controls.
  - **Memory Corruption (ICCM/DCCM):** DMA masters might be able to write directly to ICCM or DCCM, overwriting code or stack data.
  - **Interrupt Hijacking (PIC):** DMA writes to the Programmable Interrupt Controller (PIC) could disable critical security interrupts or redirect them to malicious handlers.

### 2.3. Side-Channel Attacks (Information Disclosure)

**Threat:** Observable physical properties (timing, power, EM) varying based on processed data or instructions.

- **Firmware Impact:**
  - **Variable-Time Arithmetic:** The hardware divider (`css_mcu0_el2_exu_div_ctl`) is explicitly identified as non-constant time. Firmware **must not** use hardware division or remainder operations for secret or cryptographic data.
  - **Microarchitectural State:** Branch predictor state and load-store buffers can create timing side-channels. Firmware must ensure context switches or boundary crossings sanitize these structures if they share state across privilege levels.
  - **Power/EM Signatures:** Complex combinatorial logic (like BitManip or crypto engines) can leak data. Firmware should utilize masking or other algorithmic countermeasures when processing highly sensitive keys.

### 2.4. Access Control & Privilege Escalation

**Threat:** Hardware implementation details inadvertently bypassing privilege separation.

- **Firmware Impact:**
  - **Hardcoded Bus Privilege (AxPROT):** If hardware bus buffers hardcode transactions as "Privileged" (as noted in some LSU analyses), User-mode code running on the core might be able to access Machine-mode resources on the bus. Firmware cannot rely on hardware bus-level protection if this is the case.
  - **Tag Abuse:** If bus user tags (`a_user`) default to privileged states or are not strictly checked, escalation is possible.

### 2.5. Debug & Test Interface Abuse

**Threat:** JTAG and Scan mode interfaces allowing direct read/write access to internal state.

- **Firmware Impact:**
  - **State Extraction:** If not securely locked, JTAG can dump ICCM, DCCM, and register contents, exposing keys and IP.
  - **Execution Control:** Debug interfaces can halt the core or inject instructions.
  - **Mitigation:** Firmware must verify that debug interfaces are locked in production states (reading lifecycle or security state registers) before handling any sensitive assets.

### 2.6. Error Handling & Resilience

**Threat:** Hardware errors (ECC, bus protocol violations) leading to undefined states or DoS.

- **Firmware Impact:**
  - **Fail-Secure Requirements:** Firmware must handle hardware exceptions (NMI, Access Faults) securely. It must not leak context or sensitive data during an exception.
  - **Imprecise Errors:** Handling imprecise bus errors requires careful design to ensure security state is not lost or bypassed.
