<!---
Markdown description for SystemRDL register map.

Don't override. Generated from: caliptra_fpga_realtime_regs
  - caliptra_fpga_realtime_regs.rdl
-->

## caliptra_fpga_realtime_regs address map

- Absolute Address: 0x0
- Base Offset: 0x0
- Size: 0xA4011010

|  Offset  |  Identifier  |Name|
|----------|--------------|----|
|0xA4010000|interface_regs|  — |
|0xA4011000|   fifo_regs  |  — |

## interface_regs register file

- Absolute Address: 0xA4010000
- Base Offset: 0xA4010000
- Size: 0x100

|Offset|        Identifier        |Name|
|------|--------------------------|----|
| 0x00 |        fpga_magic        |  — |
| 0x04 |       fpga_version       |  — |
| 0x08 |          control         |  — |
| 0x0C |          status          |  — |
| 0x10 |          pauser          |  — |
| 0x14 |       itrng_divisor      |  — |
| 0x18 |        cycle_count       |  — |
| 0x30 |  generic_input_wires[0]  |  — |
| 0x34 |  generic_input_wires[1]  |  — |
| 0x38 |  generic_output_wires[0] |  — |
| 0x3C |  generic_output_wires[1] |  — |
| 0x40 |     cptra_obf_key[0]     |  — |
| 0x44 |     cptra_obf_key[1]     |  — |
| 0x48 |     cptra_obf_key[2]     |  — |
| 0x4C |     cptra_obf_key[3]     |  — |
| 0x50 |     cptra_obf_key[4]     |  — |
| 0x54 |     cptra_obf_key[5]     |  — |
| 0x58 |     cptra_obf_key[6]     |  — |
| 0x5C |     cptra_obf_key[7]     |  — |
| 0x60 |   cptra_csr_hmac_key[0]  |  — |
| 0x64 |   cptra_csr_hmac_key[1]  |  — |
| 0x68 |   cptra_csr_hmac_key[2]  |  — |
| 0x6C |   cptra_csr_hmac_key[3]  |  — |
| 0x70 |   cptra_csr_hmac_key[4]  |  — |
| 0x74 |   cptra_csr_hmac_key[5]  |  — |
| 0x78 |   cptra_csr_hmac_key[6]  |  — |
| 0x7C |   cptra_csr_hmac_key[7]  |  — |
| 0x80 |   cptra_csr_hmac_key[8]  |  — |
| 0x84 |   cptra_csr_hmac_key[9]  |  — |
| 0x88 |  cptra_csr_hmac_key[10]  |  — |
| 0x8C |  cptra_csr_hmac_key[11]  |  — |
| 0x90 |  cptra_csr_hmac_key[12]  |  — |
| 0x94 |  cptra_csr_hmac_key[13]  |  — |
| 0x98 |  cptra_csr_hmac_key[14]  |  — |
| 0x9C |  cptra_csr_hmac_key[15]  |  — |
| 0xA0 |   cptra_obf_uds_seed[0]  |  — |
| 0xA4 |   cptra_obf_uds_seed[1]  |  — |
| 0xA8 |   cptra_obf_uds_seed[2]  |  — |
| 0xAC |   cptra_obf_uds_seed[3]  |  — |
| 0xB0 |   cptra_obf_uds_seed[4]  |  — |
| 0xB4 |   cptra_obf_uds_seed[5]  |  — |
| 0xB8 |   cptra_obf_uds_seed[6]  |  — |
| 0xBC |   cptra_obf_uds_seed[7]  |  — |
| 0xC0 |   cptra_obf_uds_seed[8]  |  — |
| 0xC4 |   cptra_obf_uds_seed[9]  |  — |
| 0xC8 |  cptra_obf_uds_seed[10]  |  — |
| 0xCC |  cptra_obf_uds_seed[11]  |  — |
| 0xD0 |  cptra_obf_uds_seed[12]  |  — |
| 0xD4 |  cptra_obf_uds_seed[13]  |  — |
| 0xD8 |  cptra_obf_uds_seed[14]  |  — |
| 0xDC |  cptra_obf_uds_seed[15]  |  — |
| 0xE0 |cptra_obf_field_entropy[0]|  — |
| 0xE4 |cptra_obf_field_entropy[1]|  — |
| 0xE8 |cptra_obf_field_entropy[2]|  — |
| 0xEC |cptra_obf_field_entropy[3]|  — |
| 0xF0 |cptra_obf_field_entropy[4]|  — |
| 0xF4 |cptra_obf_field_entropy[5]|  — |
| 0xF8 |cptra_obf_field_entropy[6]|  — |
| 0xFC |cptra_obf_field_entropy[7]|  — |

### fpga_magic register

- Absolute Address: 0xA4010000
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|   Reset  |Name|
|----|----------|------|----------|----|
|31:0|fpga_magic|   r  |0x52545043|  — |

#### fpga_magic field

<p>Ascii "CPTR" to check that the image is valid.</p>

### fpga_version register

- Absolute Address: 0xA4010004
- Base Offset: 0x4
- Size: 0x4

|Bits| Identifier |Access|Reset|Name|
|----|------------|------|-----|----|
|31:0|fpga_version|   r  | 0x0 |  — |

#### fpga_version field

<p>Git commit of HEAD the FPGA was built with.</p>

### control register

- Absolute Address: 0xA4010008
- Base Offset: 0x8
- Size: 0x4

|Bits|         Identifier        |Access|Reset|Name|
|----|---------------------------|------|-----|----|
|  0 |       cptra_pwrgood       |  rw  | 0x0 |  — |
|  1 |        cptra_rst_b        |  rw  | 0x0 |  — |
|  2 |   cptra_obf_uds_seed_vld  |  rw  | 0x0 |  — |
|  3 |cptra_obf_field_entropy_vld|  rw  | 0x0 |  — |
|  4 |      ss_debug_locked      |  rw  | 0x0 |  — |
| 6:5|    ss_device_lifecycle    |  rw  | 0x0 |  — |
|  7 |         scan_mode         |  rw  | 0x0 |  — |
|  8 |      bootfsm_brkpoint     |  rw  | 0x0 |  — |
|  9 |      ss_debug_intent      |  rw  | 0x0 |  — |

### status register

- Absolute Address: 0xA401000C
- Base Offset: 0xC
- Size: 0x4

|Bits|       Identifier      |Access|Reset|Name|
|----|-----------------------|------|-----|----|
|  0 |   cptra_error_fatal   |   r  | 0x0 |  — |
|  1 | cptra_error_non_fatal |   r  | 0x0 |  — |
|  2 |    ready_for_fuses    |   r  | 0x0 |  — |
|  3 |ready_for_mb_processing|   r  | 0x0 |  — |
|  4 |   ready_for_runtime   |   r  | 0x0 |  — |
|  5 |   mailbox_data_avail  |   r  | 0x0 |  — |
|  6 |   mailbox_flow_done   |   r  | 0x0 |  — |

### pauser register

- Absolute Address: 0xA4010010
- Base Offset: 0x10
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  pauser  |  rw  | 0x0 |  — |

### itrng_divisor register

- Absolute Address: 0xA4010014
- Base Offset: 0x14
- Size: 0x4

|Bits|  Identifier |Access|Reset|Name|
|----|-------------|------|-----|----|
|31:0|itrng_divisor|  rw  | 0x0 |  — |

### cycle_count register

- Absolute Address: 0xA4010018
- Base Offset: 0x18
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|cycle_count|   r  | 0x0 |  — |

### generic_input_wires register

- Absolute Address: 0xA4010030
- Base Offset: 0x30
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### generic_input_wires register

- Absolute Address: 0xA4010034
- Base Offset: 0x30
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### generic_output_wires register

- Absolute Address: 0xA4010038
- Base Offset: 0x38
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### generic_output_wires register

- Absolute Address: 0xA401003C
- Base Offset: 0x38
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010040
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010044
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010048
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA401004C
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010050
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010054
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010058
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA401005C
- Base Offset: 0x40
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010060
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010064
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010068
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401006C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010070
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010074
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010078
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401007C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010080
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010084
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010088
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401008C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010090
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010094
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA4010098
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_csr_hmac_key register

- Absolute Address: 0xA401009C
- Base Offset: 0x60
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100A0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100A4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100A8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100AC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100B0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100B4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100B8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100BC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100C0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100C4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100C8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100CC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100D0
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100D4
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100D8
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_uds_seed register

- Absolute Address: 0xA40100DC
- Base Offset: 0xA0
- Size: 0x4
- Array Dimensions: [16]
- Array Stride: 0x4
- Total Size: 0x40

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100E0
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100E4
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100E8
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100EC
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100F0
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100F4
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100F8
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_field_entropy register

- Absolute Address: 0xA40100FC
- Base Offset: 0xE0
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

## fifo_regs register file

- Absolute Address: 0xA4011000
- Base Offset: 0xA4011000
- Size: 0x10

|Offset|    Identifier   |Name|
|------|-----------------|----|
|  0x0 |  log_fifo_data  |  — |
|  0x4 | log_fifo_status |  — |
|  0x8 | itrng_fifo_data |  — |
|  0xC |itrng_fifo_status|  — |

### log_fifo_data register

- Absolute Address: 0xA4011000
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
| 7:0| next_char|   r  | 0x0 |  — |
|  8 |char_valid|   r  | 0x0 |  — |

### log_fifo_status register

- Absolute Address: 0xA4011004
- Base Offset: 0x4
- Size: 0x4

|Bits|  Identifier  |Access|Reset|Name|
|----|--------------|------|-----|----|
|  0 |log_fifo_empty|   r  | 0x0 |  — |
|  1 | log_fifo_full|   r  | 0x0 |  — |

### itrng_fifo_data register

- Absolute Address: 0xA4011008
- Base Offset: 0x8
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|itrng_data|  rw  | 0x0 |  — |

### itrng_fifo_status register

- Absolute Address: 0xA401100C
- Base Offset: 0xC
- Size: 0x4

|Bits|   Identifier   |Access|Reset|Name|
|----|----------------|------|-----|----|
|  0 |itrng_fifo_empty|   r  | 0x0 |  — |
|  1 | itrng_fifo_full|   r  | 0x0 |  — |
|  2 |itrng_fifo_reset|  rw  | 0x0 |  — |
