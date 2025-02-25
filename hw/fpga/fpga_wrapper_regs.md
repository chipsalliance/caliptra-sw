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
- Size: 0x48

|Offset|       Identifier      |Name|
|------|-----------------------|----|
| 0x00 | generic_input_wires[0]|  — |
| 0x04 | generic_input_wires[1]|  — |
| 0x08 |generic_output_wires[0]|  — |
| 0x0C |generic_output_wires[1]|  — |
| 0x10 |    cptra_obf_key[0]   |  — |
| 0x14 |    cptra_obf_key[1]   |  — |
| 0x18 |    cptra_obf_key[2]   |  — |
| 0x1C |    cptra_obf_key[3]   |  — |
| 0x20 |    cptra_obf_key[4]   |  — |
| 0x24 |    cptra_obf_key[5]   |  — |
| 0x28 |    cptra_obf_key[6]   |  — |
| 0x2C |    cptra_obf_key[7]   |  — |
| 0x30 |        control        |  — |
| 0x34 |         status        |  — |
| 0x38 |         pauser        |  — |
| 0x3C |     itrng_divisor     |  — |
| 0x40 |      cycle_count      |  — |
| 0x44 |      fpga_version     |  — |

### generic_input_wires register

- Absolute Address: 0xA4010000
- Base Offset: 0x0
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### generic_input_wires register

- Absolute Address: 0xA4010004
- Base Offset: 0x0
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### generic_output_wires register

- Absolute Address: 0xA4010008
- Base Offset: 0x8
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### generic_output_wires register

- Absolute Address: 0xA401000C
- Base Offset: 0x8
- Size: 0x4
- Array Dimensions: [2]
- Array Stride: 0x4
- Total Size: 0x8

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |   r  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010010
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010014
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010018
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA401001C
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010020
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010024
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA4010028
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### cptra_obf_key register

- Absolute Address: 0xA401002C
- Base Offset: 0x10
- Size: 0x4
- Array Dimensions: [8]
- Array Stride: 0x4
- Total Size: 0x20

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|   value  |  rw  | 0x0 |  — |

### control register

- Absolute Address: 0xA4010030
- Base Offset: 0x30
- Size: 0x4

|Bits|     Identifier    |Access|Reset|Name|
|----|-------------------|------|-----|----|
|  0 |   cptra_pwrgood   |  rw  | 0x0 |  — |
|  1 |    cptra_rst_b    |  rw  | 0x0 |  — |
|  2 |  ss_debug_locked  |  rw  | 0x0 |  — |
| 4:3|ss_device_lifecycle|  rw  | 0x0 |  — |
|  5 |     scan_mode     |  rw  | 0x0 |  — |
|  6 |  bootfsm_brkpoint |  rw  | 0x0 |  — |

### status register

- Absolute Address: 0xA4010034
- Base Offset: 0x34
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

- Absolute Address: 0xA4010038
- Base Offset: 0x38
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  pauser  |  rw  | 0x0 |  — |

### itrng_divisor register

- Absolute Address: 0xA401003C
- Base Offset: 0x3C
- Size: 0x4

|Bits|  Identifier |Access|Reset|Name|
|----|-------------|------|-----|----|
|31:0|itrng_divisor|  rw  | 0x0 |  — |

### cycle_count register

- Absolute Address: 0xA4010040
- Base Offset: 0x40
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|cycle_count|   r  | 0x0 |  — |

### fpga_version register

- Absolute Address: 0xA4010044
- Base Offset: 0x44
- Size: 0x4

|Bits| Identifier |Access|Reset|Name|
|----|------------|------|-----|----|
|31:0|fpga_version|   r  | 0x0 |  — |

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
