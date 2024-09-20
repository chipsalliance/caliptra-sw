<!---
Markdown description for SystemRDL register map.

Don't override. Generated from: I3CCSR
-->

## I3CCSR address map

- Absolute Address: 0x0
- Base Offset: 0x0
- Size: 0x1000

|Offset|Identifier|                  Name                  |
|------|----------|----------------------------------------|
| 0x000|  I3CBase |I3C Capability and Operational Registers|
| 0x080|PIOControl|            Programmable I/O            |
| 0x100|  I3C_EC  |          Extended Capabilities         |
| 0x400|    DAT   |          Device Address Table          |
| 0x800|    DCT   |       Device Characteristic Table      |

## I3CBase register file

- Absolute Address: 0x0
- Base Offset: 0x0
- Size: 0x6C

|Offset|         Identifier        |                    Name                    |
|------|---------------------------|--------------------------------------------|
| 0x00 |        HCI_VERSION        |                 HCI Version                |
| 0x04 |         HC_CONTROL        |                   Control                  |
| 0x08 |   CONTROLLER_DEVICE_ADDR  |               Dynamic address              |
| 0x0C |      HC_CAPABILITIES      |                Capabilities                |
| 0x10 |       RESET_CONTROL       |               Reset controls               |
| 0x14 |       PRESENT_STATE       |              Active controller             |
| 0x20 |        INTR_STATUS        |                   Status                   |
| 0x24 |     INTR_STATUS_ENABLE    |           Enable status reporting          |
| 0x28 |     INTR_SIGNAL_ENABLE    |          Enable status interrupts          |
| 0x2C |         INTR_FORCE        |         Force status and interrupt         |
| 0x30 |     DAT_SECTION_OFFSET    |             DAT section offset             |
| 0x34 |     DCT_SECTION_OFFSET    |             DCT section offset             |
| 0x38 |RING_HEADERS_SECTION_OFFSET|             Ring section offset            |
| 0x3C |     PIO_SECTION_OFFSET    |             PIO section offset             |
| 0x40 |  EXT_CAPS_SECTION_OFFSET  |    Extended capabilities section offset    |
| 0x4C |      INT_CTRL_CMDS_EN     |                MIPI commands               |
| 0x58 |      IBI_NOTIFY_CTRL      |         I3C interrupts notification        |
| 0x5C |    IBI_DATA_ABORT_CTRL    |              IBI data control              |
| 0x60 |      DEV_CTX_BASE_LO      | Device context memory address lower 32 bits|
| 0x64 |      DEV_CTX_BASE_HI      |Device context memory address higher 32 bits|
| 0x68 |         DEV_CTX_SG        |                 SG control                 |

### HCI_VERSION register

- Absolute Address: 0x0
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  VERSION |   r  |0x120|  — |

### HC_CONTROL register

- Absolute Address: 0x4
- Base Offset: 0x4
- Size: 0x4

|Bits|       Identifier      |  Access |Reset|          Name         |
|----|-----------------------|---------|-----|-----------------------|
|  0 |      IBA_INCLUDE      |    rw   | 0x0 |      IBA_INCLUDE      |
|  3 |    AUTOCMD_DATA_RPT   |    r    | 0x0 |    AUTOCMD_DATA_RPT   |
|  4 |  DATA_BYTE_ORDER_MODE |    r    | 0x0 |  DATA_BYTE_ORDER_MODE |
|  6 |     MODE_SELECTOR     |    r    | 0x1 |     MODE_SELECTOR     |
|  7 |    I2C_DEV_PRESENT    |    rw   | 0x0 |    I2C_DEV_PRESENT    |
|  8 |     HOT_JOIN_CTRL     |    rw   | 0x0 |     HOT_JOIN_CTRL     |
| 12 |HALT_ON_CMD_SEQ_TIMEOUT|    rw   | 0x0 |HALT_ON_CMD_SEQ_TIMEOUT|
| 29 |         ABORT         |    rw   | 0x0 |         ABORT         |
| 30 |         RESUME        |rw, woclr| 0x0 |         RESUME        |
| 31 |       BUS_ENABLE      |    rw   | 0x0 |       BUS_ENABLE      |

#### IBA_INCLUDE field

<p>Include I3C Broadcast Address:</p>
<p>0 - skips I3C Broadcast Address for private transfers</p>
<p>1 - includes I3C Broadcast Address for private transfers</p>

#### AUTOCMD_DATA_RPT field

<p>Auto-Command Data Report:</p>
<p>0 - coalesced reporting</p>
<p>1 - separated reporting</p>

#### DATA_BYTE_ORDER_MODE field

<p>Data Byte Ordering Mode:</p>
<p>0 - Little Endian</p>
<p>1 - Big Endian</p>

#### MODE_SELECTOR field

<p>DMA/PIO Mode Selector:</p>
<p>0 - DMA</p>
<p>1 - PIO</p>

#### I2C_DEV_PRESENT field

<p>I2C Device Present on Bus:</p>
<p>0 - pure I3C bus</p>
<p>1 - legacy I2C devices on the bus</p>

#### HOT_JOIN_CTRL field

<p>Hot-Join ACK/NACK Control:</p>
<p>0 - ACK Hot-Join request</p>
<p>1 - NACK Hot-Join request and send Broadcast CCC to disable Hot-Join</p>

#### HALT_ON_CMD_SEQ_TIMEOUT field

<p>Halt on Command Sequence Timeout when set to 1</p>

#### ABORT field

<p>Host Controller Abort when set to 1</p>

#### RESUME field

<p>Host Controller Resume:</p>
<p>0 - Controller is running</p>
<p>1 - Controller is suspended</p>
<p>Write 1 to resume Controller operations.</p>

#### BUS_ENABLE field

<p>Host Controller Bus Enable</p>

### CONTROLLER_DEVICE_ADDR register

- Absolute Address: 0x8
- Base Offset: 0x8
- Size: 0x4

| Bits|    Identifier    |Access|Reset|       Name       |
|-----|------------------|------|-----|------------------|
|22:16|   DYNAMIC_ADDR   |  rw  | 0x0 |   DYNAMIC_ADDR   |
|  31 |DYNAMIC_ADDR_VALID|  rw  | 0x0 |DYNAMIC_ADDR_VALID|

#### DYNAMIC_ADDR field

<p>Device Dynamic Address</p>

#### DYNAMIC_ADDR_VALID field

<p>Dynamic Address is Valid:</p>
<p>0 - dynamic address is invalid</p>
<p>1 - dynamic address is valid</p>

### HC_CAPABILITIES register

- Absolute Address: 0xC
- Base Offset: 0xC
- Size: 0x4

| Bits|      Identifier     |Access|Reset|         Name        |
|-----|---------------------|------|-----|---------------------|
|  2  |    COMBO_COMMAND    |   r  | 0x0 |    COMBO_COMMAND    |
|  3  |     AUTO_COMMAND    |   r  | 0x0 |     AUTO_COMMAND    |
|  5  |    STANDBY_CR_CAP   |   r  | 0x0 |    STANDBY_CR_CAP   |
|  6  |      HDR_DDR_EN     |   r  | 0x0 |      HDR_DDR_EN     |
|  7  |      HDR_TS_EN      |   r  | 0x0 |      HDR_TS_EN      |
|  10 |   CMD_CCC_DEFBYTE   |   r  | 0x1 |   CMD_CCC_DEFBYTE   |
|  11 |  IBI_DATA_ABORT_EN  |   r  | 0x0 |  IBI_DATA_ABORT_EN  |
|  12 | IBI_CREDIT_COUNT_EN |   r  | 0x0 | IBI_CREDIT_COUNT_EN |
|  13 |SCHEDULED_COMMANDS_EN|   r  | 0x0 |SCHEDULED_COMMANDS_EN|
|21:20|       CMD_SIZE      |   r  | 0x0 |       CMD_SIZE      |
|  28 | SG_CAPABILITY_CR_EN |   r  | 0x0 | SG_CAPABILITY_CR_EN |
|  29 | SG_CAPABILITY_IBI_EN|   r  | 0x0 | SG_CAPABILITY_IBI_EN|
|  30 | SG_CAPABILITY_DC_EN |   r  | 0x0 | SG_CAPABILITY_DC_EN |

#### COMBO_COMMAND field

<p>Controller combined command:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### AUTO_COMMAND field

<p>Automatic read command on IBI:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### STANDBY_CR_CAP field

<p>Switching from active to standby mode:</p>
<p>0 - not supported, this controller is always active on I3C</p>
<p>1- supported, this controller can hand off I3C to secondary controller</p>

#### HDR_DDR_EN field

<p>HDR-DDR transfers:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### HDR_TS_EN field

<p>HDR-Ternary transfers:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### CMD_CCC_DEFBYTE field

<p>CCC with defining byte:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### IBI_DATA_ABORT_EN field

<p>Controller IBI data abort:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### IBI_CREDIT_COUNT_EN field

<p>Controller IBI credit count:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### SCHEDULED_COMMANDS_EN field

<p>Controller command scheduling:</p>
<p>0 - not supported</p>
<p>1 - supported</p>

#### CMD_SIZE field

<p>Size and structure of the Command Descriptor:</p>
<p>2'b0: 2 DWORDs,</p>
<p>all other reserved.</p>

#### SG_CAPABILITY_CR_EN field

<p>DMA only: Command and Response rings memory:</p>
<p>0 - must be physically continuous</p>
<p>1 - controller supports scatter-gather</p>

#### SG_CAPABILITY_IBI_EN field

<p>DMA only: IBI status and IBI Data rings memory:</p>
<p>0 - must be physically continuous</p>
<p>1 - controller supports scatter-gather</p>

#### SG_CAPABILITY_DC_EN field

<p>Device context memory:</p>
<p>0 - must be physically continuous</p>
<p>1 - controller supports scatter-gather</p>

### RESET_CONTROL register

- Absolute Address: 0x10
- Base Offset: 0x10
- Size: 0x4

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
|  0 |   SOFT_RST   |  rw  | 0x0 |   SOFT_RST   |
|  1 | CMD_QUEUE_RST|  rw  | 0x0 | CMD_QUEUE_RST|
|  2 |RESP_QUEUE_RST|  rw  | 0x0 |RESP_QUEUE_RST|
|  3 |  TX_FIFO_RST |  rw  | 0x0 |  TX_FIFO_RST |
|  4 |  RX_FIFO_RST |  rw  | 0x0 |  RX_FIFO_RST |
|  5 | IBI_QUEUE_RST|  rw  | 0x0 | IBI_QUEUE_RST|

#### SOFT_RST field

<p>Reset controller from software.</p>

#### CMD_QUEUE_RST field

<p>Clear command queue from software. Valid only in PIO mode.</p>

#### RESP_QUEUE_RST field

<p>Clear response queue from software. Valid only in PIO mode.</p>

#### TX_FIFO_RST field

<p>Clear TX FIFO from software. Valid only in PIO mode.</p>

#### RX_FIFO_RST field

<p>Clear RX FIFO from software. Valid only in PIO mode.</p>

#### IBI_QUEUE_RST field

<p>Clear IBI queue from software. Valid only in PIO mode.</p>

### PRESENT_STATE register

- Absolute Address: 0x14
- Base Offset: 0x14
- Size: 0x4

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
|  2 |AC_CURRENT_OWN|   r  | 0x1 |AC_CURRENT_OWN|

#### AC_CURRENT_OWN field

<p>Controller I3C state:</p>
<p>0 - not bus owner</p>
<p>1 - bus owner</p>

### INTR_STATUS register

- Absolute Address: 0x20
- Base Offset: 0x20
- Size: 0x4

|Bits|         Identifier        |  Access |Reset|            Name           |
|----|---------------------------|---------|-----|---------------------------|
| 10 |    HC_INTERNAL_ERR_STAT   |rw, woclr| 0x0 |    HC_INTERNAL_ERR_STAT   |
| 11 |     HC_SEQ_CANCEL_STAT    |rw, woclr| 0x0 |     HC_SEQ_CANCEL_STAT    |
| 12 | HC_WARN_CMD_SEQ_STALL_STAT|rw, woclr| 0x0 | HC_WARN_CMD_SEQ_STALL_STAT|
| 13 |HC_ERR_CMD_SEQ_TIMEOUT_STAT|rw, woclr| 0x0 |HC_ERR_CMD_SEQ_TIMEOUT_STAT|
| 14 | SCHED_CMD_MISSED_TICK_STAT|rw, woclr| 0x0 | SCHED_CMD_MISSED_TICK_STAT|

#### HC_INTERNAL_ERR_STAT field

<p>Controller internal unrecoverable error.</p>

#### HC_SEQ_CANCEL_STAT field

<p>Controller had to cancel command sequence.</p>

#### HC_WARN_CMD_SEQ_STALL_STAT field

<p>Clock stalled due to lack of commands.</p>

#### HC_ERR_CMD_SEQ_TIMEOUT_STAT field

<p>Command timeout after prolonged stall.</p>

#### SCHED_CMD_MISSED_TICK_STAT field

<p>Scheduled commands could be executed due to controller being busy.</p>

### INTR_STATUS_ENABLE register

- Absolute Address: 0x24
- Base Offset: 0x24
- Size: 0x4

|Bits|          Identifier          |Access|Reset|             Name             |
|----|------------------------------|------|-----|------------------------------|
| 10 |    HC_INTERNAL_ERR_STAT_EN   |  rw  | 0x0 |    HC_INTERNAL_ERR_STAT_EN   |
| 11 |     HC_SEQ_CANCEL_STAT_EN    |  rw  | 0x0 |     HC_SEQ_CANCEL_STAT_EN    |
| 12 | HC_WARN_CMD_SEQ_STALL_STAT_EN|  rw  | 0x0 | HC_WARN_CMD_SEQ_STALL_STAT_EN|
| 13 |HC_ERR_CMD_SEQ_TIMEOUT_STAT_EN|  rw  | 0x0 |HC_ERR_CMD_SEQ_TIMEOUT_STAT_EN|
| 14 | SCHED_CMD_MISSED_TICK_STAT_EN|  rw  | 0x0 | SCHED_CMD_MISSED_TICK_STAT_EN|

#### HC_INTERNAL_ERR_STAT_EN field

<p>Enable HC_INTERNAL_ERR_STAT monitoring.</p>

#### HC_SEQ_CANCEL_STAT_EN field

<p>Enable HC_SEQ_CANCEL_STAT monitoring.</p>

#### HC_WARN_CMD_SEQ_STALL_STAT_EN field

<p>Enable HC_WARN_CMD_SEQ_STALL_STAT monitoring.</p>

#### HC_ERR_CMD_SEQ_TIMEOUT_STAT_EN field

<p>Enable HC_ERR_CMD_SEQ_TIMEOUT_STAT monitoring.</p>

#### SCHED_CMD_MISSED_TICK_STAT_EN field

<p>Enable SCHED_CMD_MISSED_TICK_STAT monitoring.</p>

### INTR_SIGNAL_ENABLE register

- Absolute Address: 0x28
- Base Offset: 0x28
- Size: 0x4

|Bits|           Identifier           |Access|Reset|              Name              |
|----|--------------------------------|------|-----|--------------------------------|
| 10 |    HC_INTERNAL_ERR_SIGNAL_EN   |  rw  | 0x0 |    HC_INTERNAL_ERR_SIGNAL_EN   |
| 11 |     HC_SEQ_CANCEL_SIGNAL_EN    |  rw  | 0x0 |     HC_SEQ_CANCEL_SIGNAL_EN    |
| 12 | HC_WARN_CMD_SEQ_STALL_SIGNAL_EN|  rw  | 0x0 | HC_WARN_CMD_SEQ_STALL_SIGNAL_EN|
| 13 |HC_ERR_CMD_SEQ_TIMEOUT_SIGNAL_EN|  rw  | 0x0 |HC_ERR_CMD_SEQ_TIMEOUT_SIGNAL_EN|
| 14 | SCHED_CMD_MISSED_TICK_SIGNAL_EN|  rw  | 0x0 | SCHED_CMD_MISSED_TICK_SIGNAL_EN|

#### HC_INTERNAL_ERR_SIGNAL_EN field

<p>Enable HC_INTERNAL_ERR_STAT interrupt.</p>

#### HC_SEQ_CANCEL_SIGNAL_EN field

<p>Enable HC_SEQ_CANCEL_STAT interrupt.</p>

#### HC_WARN_CMD_SEQ_STALL_SIGNAL_EN field

<p>Enable HC_WARN_CMD_SEQ_STALL_STAT interrupt.</p>

#### HC_ERR_CMD_SEQ_TIMEOUT_SIGNAL_EN field

<p>Enable HC_ERR_CMD_SEQ_TIMEOUT_STAT interrupt.</p>

#### SCHED_CMD_MISSED_TICK_SIGNAL_EN field

<p>Enable SCHED_CMD_MISSED_TICK_STAT interrupt.</p>

### INTR_FORCE register

- Absolute Address: 0x2C
- Base Offset: 0x2C
- Size: 0x4

|Bits|         Identifier         |Access|Reset|            Name            |
|----|----------------------------|------|-----|----------------------------|
| 10 |    HC_INTERNAL_ERR_FORCE   |   w  | 0x0 |    HC_INTERNAL_ERR_FORCE   |
| 11 |     HC_SEQ_CANCEL_FORCE    |   w  | 0x0 |     HC_SEQ_CANCEL_FORCE    |
| 12 | HC_WARN_CMD_SEQ_STALL_FORCE|   w  | 0x0 | HC_WARN_CMD_SEQ_STALL_FORCE|
| 13 |HC_ERR_CMD_SEQ_TIMEOUT_FORCE|   w  | 0x0 |HC_ERR_CMD_SEQ_TIMEOUT_FORCE|
| 14 | SCHED_CMD_MISSED_TICK_FORCE|   w  | 0x0 | SCHED_CMD_MISSED_TICK_FORCE|

#### HC_INTERNAL_ERR_FORCE field

<p>Force HC_INTERNAL_ERR_STAT interrupt.</p>

#### HC_SEQ_CANCEL_FORCE field

<p>Force HC_SEQ_CANCEL_STAT interrupt.</p>

#### HC_WARN_CMD_SEQ_STALL_FORCE field

<p>Force HC_WARN_CMD_SEQ_STALL_STAT interrupt.</p>

#### HC_ERR_CMD_SEQ_TIMEOUT_FORCE field

<p>Force HC_ERR_CMD_SEQ_TIMEOUT_STAT interrupt.</p>

#### SCHED_CMD_MISSED_TICK_FORCE field

<p>Force SCHED_CMD_MISSED_TICK_STAT interrupt.</p>

### DAT_SECTION_OFFSET register

- Absolute Address: 0x30
- Base Offset: 0x30
- Size: 0x4

| Bits| Identifier |Access|Reset|    Name    |
|-----|------------|------|-----|------------|
| 11:0|TABLE_OFFSET|   r  |0x400|TABLE_OFFSET|
|18:12| TABLE_SIZE |   r  | 0x7F| TABLE_SIZE |
|31:28| ENTRY_SIZE |   r  | 0x0 | ENTRY_SIZE |

#### TABLE_OFFSET field

<p>DAT entry offset in respect to BASE address.</p>

#### TABLE_SIZE field

<p>Max number of DAT entries.</p>

#### ENTRY_SIZE field

<p>Individual DAT entry size.
0 - 2 DWRODs,
1:15 - reserved.</p>

### DCT_SECTION_OFFSET register

- Absolute Address: 0x34
- Base Offset: 0x34
- Size: 0x4

| Bits| Identifier |Access|Reset|    Name    |
|-----|------------|------|-----|------------|
| 11:0|TABLE_OFFSET|   r  |0x800|TABLE_OFFSET|
|18:12| TABLE_SIZE |   r  | 0x7F| TABLE_SIZE |
|23:19| TABLE_INDEX|  rw  | 0x0 | TABLE_INDEX|
|31:28| ENTRY_SIZE |   r  | 0x0 | ENTRY_SIZE |

#### TABLE_OFFSET field

<p>DCT entry offset in respect to BASE address.</p>

#### TABLE_SIZE field

<p>Max number of DCT entries.</p>

#### TABLE_INDEX field

<p>Index to DCT used during ENTDAA.</p>

#### ENTRY_SIZE field

<p>Individual DCT entry size.</p>
<p>0 - 4 DWORDs,</p>
<p>1:15 - Reserved.</p>

### RING_HEADERS_SECTION_OFFSET register

- Absolute Address: 0x38
- Base Offset: 0x38
- Size: 0x4

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
|15:0|SECTION_OFFSET|   r  | 0x0 |SECTION_OFFSET|

#### SECTION_OFFSET field

<p>DMA ring headers section offset. Invalid if 0.</p>

### PIO_SECTION_OFFSET register

- Absolute Address: 0x3C
- Base Offset: 0x3C
- Size: 0x4

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
|15:0|SECTION_OFFSET|   r  | 0x80|SECTION_OFFSET|

#### SECTION_OFFSET field

<p>PIO section offset. Invalid if 0.</p>

### EXT_CAPS_SECTION_OFFSET register

- Absolute Address: 0x40
- Base Offset: 0x40
- Size: 0x4

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
|15:0|SECTION_OFFSET|   r  |0x100|SECTION_OFFSET|

#### SECTION_OFFSET field

<p>Extended Capabilities section offset. Invalid if 0.</p>

### INT_CTRL_CMDS_EN register

- Absolute Address: 0x4C
- Base Offset: 0x4C
- Size: 0x4

|Bits|     Identifier    |Access|Reset|        Name       |
|----|-------------------|------|-----|-------------------|
|  0 |    ICC_SUPPORT    |   r  | 0x1 |    ICC_SUPPORT    |
|15:1|MIPI_CMDS_SUPPORTED|   r  | 0x35|MIPI_CMDS_SUPPORTED|

#### ICC_SUPPORT field

<p>Internal Control Commands:</p>
<p>1 - some or all internals commands sub-commands are supported,</p>
<p>0 - illegal.</p>

#### MIPI_CMDS_SUPPORTED field

<p>Bitmask of supported MIPI commands.</p>

### IBI_NOTIFY_CTRL register

- Absolute Address: 0x58
- Base Offset: 0x58
- Size: 0x4

|Bits|     Identifier    |Access|Reset|        Name       |
|----|-------------------|------|-----|-------------------|
|  0 | NOTIFY_HJ_REJECTED|  rw  | 0x0 | NOTIFY_HJ_REJECTED|
|  1 |NOTIFY_CRR_REJECTED|  rw  | 0x0 |NOTIFY_CRR_REJECTED|
|  3 |NOTIFY_IBI_REJECTED|  rw  | 0x0 |NOTIFY_IBI_REJECTED|

#### NOTIFY_HJ_REJECTED field

<p>Notify about rejected hot-join:</p>
<p>0 - do not enqueue rejected HJ,</p>
<p>1 = enqueue rejected HJ on IBI queue/ring.</p>

#### NOTIFY_CRR_REJECTED field

<p>Notify about rejected controller role request:</p>
<p>0 - do not enqueue rejected CRR,</p>
<p>1 = enqueue rejected CRR on IBI queue/ring.</p>

#### NOTIFY_IBI_REJECTED field

<p>Notify about rejected IBI:</p>
<p>0 - do not enqueue rejected IBI,</p>
<p>1 = enqueue rejected IBI on IBI queue/ring.</p>

### IBI_DATA_ABORT_CTRL register

- Absolute Address: 0x5C
- Base Offset: 0x5C
- Size: 0x4

| Bits|    Identifier    |Access|Reset|       Name       |
|-----|------------------|------|-----|------------------|
| 15:8|   MATCH_IBI_ID   |  rw  | 0x0 |   MATCH_IBI_ID   |
|17:16|  AFTER_N_CHUNKS  |  rw  | 0x0 |  AFTER_N_CHUNKS  |
|20:18| MATCH_STATUS_TYPE|  rw  | 0x0 | MATCH_STATUS_TYPE|
|  31 |IBI_DATA_ABORT_MON|  rw  | 0x0 |IBI_DATA_ABORT_MON|

#### MATCH_IBI_ID field

<p>IBI target address:</p>
<p>[15:9] - device address,</p>
<p>[8] - must always be set to 1'b1</p>

#### AFTER_N_CHUNKS field

<p>Number of data chunks to be allowed before forced termination:</p>
<p>0 - immediate,</p>
<p>1:3 - delay by 1-3 data chunks.</p>

#### MATCH_STATUS_TYPE field

<p>Define which IBI should be aborted:</p>
<p>3'b000 - Regular IBI,</p>
<p>3'b100 - Autocmd IBI,</p>
<p>other values - not supported.</p>

#### IBI_DATA_ABORT_MON field

<p>Enable/disable IBI monitoring logic.</p>

### DEV_CTX_BASE_LO register

- Absolute Address: 0x60
- Base Offset: 0x60
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |  BASE_LO |  rw  | 0x0 |  — |

### DEV_CTX_BASE_HI register

- Absolute Address: 0x64
- Base Offset: 0x64
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|  0 |  BASE_HI |  rw  | 0x0 |  — |

### DEV_CTX_SG register

- Absolute Address: 0x68
- Base Offset: 0x68
- Size: 0x4

|Bits|Identifier|Access|Reset|   Name  |
|----|----------|------|-----|---------|
|15:0| LIST_SIZE|   r  | 0x0 |LIST_SIZE|
| 31 |    BLP   |   r  | 0x0 |   BLP   |

#### LIST_SIZE field

<p>Number of SG entries.</p>

#### BLP field

<p>Buffer vs list pointer in device context:</p>
<p>0 - continuous physical memory region,</p>
<p>1 - pointer to SG descriptor list.</p>

## PIOControl register file

- Absolute Address: 0x80
- Base Offset: 0x80
- Size: 0x34

|Offset|      Identifier      |                                               Name                                              |
|------|----------------------|-------------------------------------------------------------------------------------------------|
| 0x00 |     COMMAND_PORT     |                                        Command issue port                                       |
| 0x04 |     RESPONSE_PORT    |                                      Command response port                                      |
| 0x08 |    XFER_DATA_PORT    |                                         Data access port                                        |
| 0x0C |       IBI_PORT       |                                    IBI descriptor access port                                   |
| 0x10 |    QUEUE_THLD_CTRL   |The Queue Threshold Control register for the Command Queue, the Response Queue, and the IBI Queue|
| 0x14 | DATA_BUFFER_THLD_CTRL|                                  RX/TX queue threshold control                                  |
| 0x18 |      QUEUE_SIZE      |                                           Queue sizes                                           |
| 0x1C |    ALT_QUEUE_SIZE    |                                      Alternate queue sizes                                      |
| 0x20 |    PIO_INTR_STATUS   |                                       PIO interrupt status                                      |
| 0x24 |PIO_INTR_STATUS_ENABLE|                                                —                                                |
| 0x28 |PIO_INTR_SIGNAL_ENABLE|                                     Interrupt Signal Enable                                     |
| 0x2C |    PIO_INTR_FORCE    |                                    PIO force interrupt status                                   |
| 0x30 |      PIO_CONTROL     |                                           PIO control                                           |

### COMMAND_PORT register

- Absolute Address: 0x80
- Base Offset: 0x0
- Size: 0x4

|Bits| Identifier |Access|Reset|       Name       |
|----|------------|------|-----|------------------|
|31:0|COMMAND_DATA|   w  |  —  |COMMAND_QUEUE_PORT|

### RESPONSE_PORT register

- Absolute Address: 0x84
- Base Offset: 0x4
- Size: 0x4

|Bits|  Identifier |Access|Reset|        Name       |
|----|-------------|------|-----|-------------------|
|31:0|RESPONSE_DATA|   r  |  —  |RESPONSE_QUEUE_PORT|

### XFER_DATA_PORT register

- Absolute Address: 0x88
- Base Offset: 0x8
- Size: 0x4

|Bits|Identifier|Access|Reset|  Name |
|----|----------|------|-----|-------|
|31:0|  TX_DATA |   w  |  —  |TX_DATA|
|31:0|  RX_DATA |   r  |  —  |RX_DATA|

### IBI_PORT register

- Absolute Address: 0x8C
- Base Offset: 0xC
- Size: 0x4

|Bits|Identifier|Access|Reset|  Name  |
|----|----------|------|-----|--------|
|  0 | IBI_DATA |   r  |  —  |IBI_DATA|

### QUEUE_THLD_CTRL register

- Absolute Address: 0x90
- Base Offset: 0x10
- Size: 0x4

| Bits|      Identifier     |Access|Reset|         Name        |
|-----|---------------------|------|-----|---------------------|
| 7:0 |  CMD_EMPTY_BUF_THLD |  rw  | 0x1 |  CMD_EMPTY_BUF_THLD |
| 15:8|    RESP_BUF_THLD    |  rw  | 0x1 |    RESP_BUF_THLD    |
|23:16|IBI_DATA_SEGMENT_SIZE|  rw  | 0x1 |IBI_DATA_SEGMENT_SIZE|
|31:24|   IBI_STATUS_THLD   |  rw  | 0x1 |   IBI_STATUS_THLD   |

#### CMD_EMPTY_BUF_THLD field

<p>Triggers CMD_QUEUE_READY_STAT interrupt when CMD queue has N or more free entries. Accepted values are 1:255</p>

#### RESP_BUF_THLD field

<p>Triggers RESP_READY_STAT interrupt when RESP queue has N or more entries. Accepted values are 1:255</p>

#### IBI_DATA_SEGMENT_SIZE field

<p>IBI Queue data segment size. Valida values are 1:63</p>

#### IBI_STATUS_THLD field

<p>Triggers IBI_STATUS_THLD_STAT interrupt when IBI queue has N or more entries. Accepted values are 1:255</p>

### DATA_BUFFER_THLD_CTRL register

- Absolute Address: 0x94
- Base Offset: 0x14
- Size: 0x4

| Bits|  Identifier |Access|Reset|     Name    |
|-----|-------------|------|-----|-------------|
| 2:0 | TX_BUF_THLD |  rw  | 0x1 | TX_BUF_THLD |
| 10:8| RX_BUF_THLD |  rw  | 0x1 | RX_BUF_THLD |
|18:16|TX_START_THLD|  rw  | 0x1 |TX_START_THLD|
|26:24|RX_START_THLD|  rw  | 0x1 |RX_START_THLD|

#### TX_BUF_THLD field

<p>Trigger TX_THLD_STAT interrupt when TX queue has 2^(N+1) or more free entries</p>

#### RX_BUF_THLD field

<p>Trigger RX_THLD_STAT interrupt when RX queue has 2^(N+1) or more entries</p>

#### TX_START_THLD field

<p>Postpone write command until TX queue has 2^(N+1) entries</p>

#### RX_START_THLD field

<p>Postpone read command until RX queue has 2^(N+1) free entries</p>

### QUEUE_SIZE register

- Absolute Address: 0x98
- Base Offset: 0x18
- Size: 0x4

| Bits|     Identifier    |Access|Reset|        Name       |
|-----|-------------------|------|-----|-------------------|
| 7:0 |   CR_QUEUE_SIZE   |   r  | 0x40|   CR_QUEUE_SIZE   |
| 15:8|  IBI_STATUS_SIZE  |   r  | 0x40|  IBI_STATUS_SIZE  |
|23:16|RX_DATA_BUFFER_SIZE|   r  | 0x5 |RX_DATA_BUFFER_SIZE|
|31:24|TX_DATA_BUFFER_SIZE|   r  | 0x5 |TX_DATA_BUFFER_SIZE|

#### CR_QUEUE_SIZE field

<p>Command/Response queue size is equal to N</p>

#### IBI_STATUS_SIZE field

<p>IBI Queue size is equal to N</p>

#### RX_DATA_BUFFER_SIZE field

<p>RX queue size is equal to 2^(N+1), where N is this field value</p>

#### TX_DATA_BUFFER_SIZE field

<p>TX queue size is equal to 2^(N+1), where N is this field value</p>

### ALT_QUEUE_SIZE register

- Absolute Address: 0x9C
- Base Offset: 0x1C
- Size: 0x4

|Bits|     Identifier    |Access|Reset|        Name       |
|----|-------------------|------|-----|-------------------|
| 7:0|ALT_RESP_QUEUE_SIZE|   r  | 0x40|ALT_RESP_QUEUE_SIZE|
| 24 | ALT_RESP_QUEUE_EN |   r  | 0x0 | ALT_RESP_QUEUE_EN |
| 28 |  EXT_IBI_QUEUE_EN |   r  | 0x0 |  EXT_IBI_QUEUE_EN |

#### ALT_RESP_QUEUE_SIZE field

<p>Valid only if ALT_RESP_QUEUE_EN is set. Contains response queue size</p>

#### ALT_RESP_QUEUE_EN field

<p>If set, response and command queues are not equal lengths, then
ALT_RESP_QUEUE_SIZE contains response queue size</p>

#### EXT_IBI_QUEUE_EN field

<p>1 indicates that IBI queue size is equal to 8*IBI_STATUS_SIZE</p>

### PIO_INTR_STATUS register

- Absolute Address: 0xA0
- Base Offset: 0x20
- Size: 0x4

|Bits|     Identifier     |  Access |Reset|        Name        |
|----|--------------------|---------|-----|--------------------|
|  0 |    TX_THLD_STAT    |    r    | 0x0 |    TX_THLD_STAT    |
|  1 |    RX_THLD_STAT    |    r    | 0x0 |    RX_THLD_STAT    |
|  2 |IBI_STATUS_THLD_STAT|    r    | 0x0 |IBI_STATUS_THLD_STAT|
|  3 |CMD_QUEUE_READY_STAT|    r    | 0x0 |CMD_QUEUE_READY_STAT|
|  4 |   RESP_READY_STAT  |    r    | 0x0 |   RESP_READY_STAT  |
|  5 | TRANSFER_ABORT_STAT|rw, woclr| 0x0 | TRANSFER_ABORT_STAT|
|  9 |  TRANSFER_ERR_STAT |rw, woclr| 0x0 |  TRANSFER_ERR_STAT |

#### TX_THLD_STAT field

<p>TX queue fulfils TX_BUF_THLD</p>

#### RX_THLD_STAT field

<p>RX queue fulfils RX_BUF_THLD</p>

#### IBI_STATUS_THLD_STAT field

<p>IBI queue fulfils IBI_STATUS_THLD</p>

#### CMD_QUEUE_READY_STAT field

<p>Command queue fulfils CMD_EMPTY_BUF_THLD</p>

#### RESP_READY_STAT field

<p>Response queue fulfils RESP_BUF_THLD</p>

#### TRANSFER_ABORT_STAT field

<p>Transfer aborted</p>

#### TRANSFER_ERR_STAT field

<p>Transfer error</p>

### PIO_INTR_STATUS_ENABLE register

- Absolute Address: 0xA4
- Base Offset: 0x24
- Size: 0x4

|Bits|       Identifier      |Access|Reset|          Name         |
|----|-----------------------|------|-----|-----------------------|
|  0 |    TX_THLD_STAT_EN    |  rw  | 0x0 |    TX_THLD_STAT_EN    |
|  1 |    RX_THLD_STAT_EN    |  rw  | 0x0 |    RX_THLD_STAT_EN    |
|  2 |IBI_STATUS_THLD_STAT_EN|  rw  | 0x0 |IBI_STATUS_THLD_STAT_EN|
|  3 |CMD_QUEUE_READY_STAT_EN|  rw  | 0x0 |CMD_QUEUE_READY_STAT_EN|
|  4 |   RESP_READY_STAT_EN  |  rw  | 0x0 |   RESP_READY_STAT_EN  |
|  5 | TRANSFER_ABORT_STAT_EN|  rw  | 0x0 | TRANSFER_ABORT_STAT_EN|
|  9 |  TRANSFER_ERR_STAT_EN |  rw  | 0x0 |  TRANSFER_ERR_STAT_EN |

#### TX_THLD_STAT_EN field

<p>Enable TX queue monitoring</p>

#### RX_THLD_STAT_EN field

<p>Enable RX queue monitoring</p>

#### IBI_STATUS_THLD_STAT_EN field

<p>Enable IBI queue monitoring</p>

#### CMD_QUEUE_READY_STAT_EN field

<p>Enable command queue monitoring</p>

#### RESP_READY_STAT_EN field

<p>Enable response queue monitoring</p>

#### TRANSFER_ABORT_STAT_EN field

<p>Enable transfer abort monitoring</p>

#### TRANSFER_ERR_STAT_EN field

<p>Enable transfer error monitoring</p>

### PIO_INTR_SIGNAL_ENABLE register

- Absolute Address: 0xA8
- Base Offset: 0x28
- Size: 0x4

|Bits|        Identifier       |Access|Reset|           Name          |
|----|-------------------------|------|-----|-------------------------|
|  0 |    TX_THLD_SIGNAL_EN    |  rw  | 0x0 |    TX_THLD_SIGNAL_EN    |
|  1 |    RX_THLD_SIGNAL_EN    |  rw  | 0x0 |    RX_THLD_SIGNAL_EN    |
|  2 |IBI_STATUS_THLD_SIGNAL_EN|  rw  | 0x0 |IBI_STATUS_THLD_SIGNAL_EN|
|  3 |CMD_QUEUE_READY_SIGNAL_EN|  rw  | 0x0 |CMD_QUEUE_READY_SIGNAL_EN|
|  4 |   RESP_READY_SIGNAL_EN  |  rw  | 0x0 |   RESP_READY_SIGNAL_EN  |
|  5 | TRANSFER_ABORT_SIGNAL_EN|  rw  | 0x0 | TRANSFER_ABORT_SIGNAL_EN|
|  9 |  TRANSFER_ERR_SIGNAL_EN |  rw  | 0x0 |  TRANSFER_ERR_SIGNAL_EN |

#### TX_THLD_SIGNAL_EN field

<p>Enable TX queue interrupt</p>

#### RX_THLD_SIGNAL_EN field

<p>Enable RX queue interrupt</p>

#### IBI_STATUS_THLD_SIGNAL_EN field

<p>Enable IBI queue interrupt</p>

#### CMD_QUEUE_READY_SIGNAL_EN field

<p>Enable command queue interrupt</p>

#### RESP_READY_SIGNAL_EN field

<p>Enable response ready interrupt</p>

#### TRANSFER_ABORT_SIGNAL_EN field

<p>Enable transfer abort interrupt</p>

#### TRANSFER_ERR_SIGNAL_EN field

<p>Enable transfer error interrupt</p>

### PIO_INTR_FORCE register

- Absolute Address: 0xAC
- Base Offset: 0x2C
- Size: 0x4

|Bits|      Identifier     |Access|Reset|         Name        |
|----|---------------------|------|-----|---------------------|
|  0 |    TX_THLD_FORCE    |   w  | 0x0 |    TX_THLD_FORCE    |
|  1 |    RX_THLD_FORCE    |   w  | 0x0 |    RX_THLD_FORCE    |
|  2 |    IBI_THLD_FORCE   |   w  | 0x0 |    IBI_THLD_FORCE   |
|  3 |CMD_QUEUE_READY_FORCE|   w  | 0x0 |CMD_QUEUE_READY_FORCE|
|  4 |   RESP_READY_FORCE  |   w  | 0x0 |   RESP_READY_FORCE  |
|  5 | TRANSFER_ABORT_FORCE|   w  | 0x0 | TRANSFER_ABORT_FORCE|
|  9 |  TRANSFER_ERR_FORCE |   w  | 0x0 |  TRANSFER_ERR_FORCE |

#### TX_THLD_FORCE field

<p>Force TX queue interrupt</p>

#### RX_THLD_FORCE field

<p>Force RX queue interrupt</p>

#### IBI_THLD_FORCE field

<p>Force IBI queue interrupt</p>

#### CMD_QUEUE_READY_FORCE field

<p>Force command queue interrupt</p>

#### RESP_READY_FORCE field

<p>Force response queue interrupt</p>

#### TRANSFER_ABORT_FORCE field

<p>Force transfer aborted</p>

#### TRANSFER_ERR_FORCE field

<p>Force transfer error</p>

### PIO_CONTROL register

- Absolute Address: 0xB0
- Base Offset: 0x30
- Size: 0x4

|Bits|Identifier|Access|Reset| Name |
|----|----------|------|-----|------|
|  0 |  ENABLE  |  rw  | 0x1 |ENABLE|
|  1 |    RS    |  rw  | 0x0 |  RS  |
|  2 |   ABORT  |  rw  | 0x0 | ABORT|

#### ENABLE field

<p>Enables PIO queues. When disabled, SW may not read from/write to PIO queues.
1 - PIO queue enable request,
0 - PIO queue disable request</p>

#### RS field

<p>Run/Stop execution of enqueued commands.
When set to 0, it holds execution of enqueued commands and runs current command to completion.
1 - PIO Queue start request,
0 - PIO Queue stop request.</p>

#### ABORT field

<p>Stop current command descriptor execution forcefully and hold remaining commands.
1 - Request PIO Abort,
0 - Resume PIO execution</p>

## I3C_EC register file

- Absolute Address: 0x100
- Base Offset: 0x100
- Size: 0x16C

|Offset|        Identifier       |               Name               |
|------|-------------------------|----------------------------------|
| 0x000|     SecFwRecoveryIf     |Secure Firmware Recovery Interface|
| 0x080|      StdbyCtrlMode      |      Standby Controller Mode     |
| 0x0C0|           TTI           |   Target Transaction Interface   |
| 0x100|        SoCMgmtIf        |     SoC Management Interface     |
| 0x160|         CtrlCfg         |         Controller Config        |
| 0x168|TERMINATION_EXTCAP_HEADER|                 —                |

## SecFwRecoveryIf register file

- Absolute Address: 0x100
- Base Offset: 0x0
- Size: 0x6C

|Offset|      Identifier      |         Name         |
|------|----------------------|----------------------|
| 0x00 |     EXTCAP_HEADER    |           —          |
| 0x04 |      PROT_CAP_0      |      PROT_CAP_0      |
| 0x08 |      PROT_CAP_1      |      PROT_CAP_1      |
| 0x0C |      PROT_CAP_2      |      PROT_CAP_2      |
| 0x10 |      PROT_CAP_3      |      PROT_CAP_3      |
| 0x14 |      DEVICE_ID_0     |      DEVICE_ID_0     |
| 0x18 |      DEVICE_ID_1     |      DEVICE_ID_1     |
| 0x1C |      DEVICE_ID_2     |      DEVICE_ID_2     |
| 0x20 |      DEVICE_ID_3     |      DEVICE_ID_3     |
| 0x24 |      DEVICE_ID_4     |      DEVICE_ID_4     |
| 0x28 |      DEVICE_ID_5     |      DEVICE_ID_5     |
| 0x2C |      DEVICE_ID_6     |      DEVICE_ID_6     |
| 0x30 |    DEVICE_STATUS_0   |    DEVICE_STATUS_0   |
| 0x34 |    DEVICE_STATUS_1   |    DEVICE_STATUS_1   |
| 0x38 |     DEVICE_RESET     |     DEVICE_RESET     |
| 0x3C |     RECOVERY_CTRL    |     RECOVERY_CTRL    |
| 0x40 |    RECOVERY_STATUS   |    RECOVERY_STATUS   |
| 0x44 |       HW_STATUS      |       HW_STATUS      |
| 0x48 | INDIRECT_FIFO_CTRL_0 | INDIRECT_FIFO_CTRL_0 |
| 0x4C | INDIRECT_FIFO_CTRL_1 | INDIRECT_FIFO_CTRL_1 |
| 0x50 |INDIRECT_FIFO_STATUS_0|INDIRECT_FIFO_STATUS_0|
| 0x54 |INDIRECT_FIFO_STATUS_1|INDIRECT_FIFO_STATUS_1|
| 0x58 |INDIRECT_FIFO_STATUS_2|INDIRECT_FIFO_STATUS_2|
| 0x5C |INDIRECT_FIFO_STATUS_3|INDIRECT_FIFO_STATUS_3|
| 0x60 |INDIRECT_FIFO_STATUS_4|INDIRECT_FIFO_STATUS_4|
| 0x64 |INDIRECT_FIFO_STATUS_5|INDIRECT_FIFO_STATUS_5|
| 0x68 |  INDIRECT_FIFO_DATA  |  INDIRECT_FIFO_DATA  |

### EXTCAP_HEADER register

- Absolute Address: 0x100
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|   Name   |
|----|----------|------|-----|----------|
| 7:0|  CAP_ID  |   r  | 0xC0|  CAP_ID  |
|23:8|CAP_LENGTH|   r  | 0x20|CAP_LENGTH|

#### CAP_ID field

<p>Extended Capability ID</p>

#### CAP_LENGTH field

<p>Capability Structure Length in DWORDs</p>

### PROT_CAP_0 register

- Absolute Address: 0x104
- Base Offset: 0x4
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### PROT_CAP_1 register

- Absolute Address: 0x108
- Base Offset: 0x8
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### PROT_CAP_2 register

- Absolute Address: 0x10C
- Base Offset: 0xC
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### PROT_CAP_3 register

- Absolute Address: 0x110
- Base Offset: 0x10
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_0 register

- Absolute Address: 0x114
- Base Offset: 0x14
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_1 register

- Absolute Address: 0x118
- Base Offset: 0x18
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_2 register

- Absolute Address: 0x11C
- Base Offset: 0x1C
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_3 register

- Absolute Address: 0x120
- Base Offset: 0x20
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_4 register

- Absolute Address: 0x124
- Base Offset: 0x24
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_5 register

- Absolute Address: 0x128
- Base Offset: 0x28
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_ID_6 register

- Absolute Address: 0x12C
- Base Offset: 0x2C
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_STATUS_0 register

- Absolute Address: 0x130
- Base Offset: 0x30
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_STATUS_1 register

- Absolute Address: 0x134
- Base Offset: 0x34
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### DEVICE_RESET register

- Absolute Address: 0x138
- Base Offset: 0x38
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### RECOVERY_CTRL register

- Absolute Address: 0x13C
- Base Offset: 0x3C
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### RECOVERY_STATUS register

- Absolute Address: 0x140
- Base Offset: 0x40
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### HW_STATUS register

- Absolute Address: 0x144
- Base Offset: 0x44
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_CTRL_0 register

- Absolute Address: 0x148
- Base Offset: 0x48
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_CTRL_1 register

- Absolute Address: 0x14C
- Base Offset: 0x4C
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_STATUS_0 register

- Absolute Address: 0x150
- Base Offset: 0x50
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_STATUS_1 register

- Absolute Address: 0x154
- Base Offset: 0x54
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_STATUS_2 register

- Absolute Address: 0x158
- Base Offset: 0x58
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_STATUS_3 register

- Absolute Address: 0x15C
- Base Offset: 0x5C
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_STATUS_4 register

- Absolute Address: 0x160
- Base Offset: 0x60
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_STATUS_5 register

- Absolute Address: 0x164
- Base Offset: 0x64
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### INDIRECT_FIFO_DATA register

- Absolute Address: 0x168
- Base Offset: 0x68
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



## StdbyCtrlMode register file

- Absolute Address: 0x180
- Base Offset: 0x80
- Size: 0x40

|Offset|           Identifier           |                    Name                    |
|------|--------------------------------|--------------------------------------------|
| 0x00 |          EXTCAP_HEADER         |                      —                     |
| 0x04 |         STBY_CR_CONTROL        |         Standby Controller Control         |
| 0x08 |       STBY_CR_DEVICE_ADDR      |      Standby Controller Device Address     |
| 0x0C |      STBY_CR_CAPABILITIES      |       Standby Controller Capabilities      |
| 0x10 |            __rsvd_0            |                 Reserved 0                 |
| 0x14 |         STBY_CR_STATUS         |          Standby Controller Status         |
| 0x18 |       STBY_CR_DEVICE_CHAR      |  Standby Controller Device Characteristics |
| 0x1C |      STBY_CR_DEVICE_PID_LO     |      Standby Controller Device PID Low     |
| 0x20 |       STBY_CR_INTR_STATUS      |     Standby Controller Interrupt Status    |
| 0x24 |            __rsvd_1            |                 Reserved 1                 |
| 0x28 |   STBY_CR_INTR_SIGNAL_ENABLE   | Standby Controller Interrupt Signal Enable |
| 0x2C |       STBY_CR_INTR_FORCE       |     Standby Controller Interrupt Force     |
| 0x30 |   STBY_CR_CCC_CONFIG_GETCAPS   |Standby Controller CCC Configuration GETCAPS|
| 0x34 |STBY_CR_CCC_CONFIG_RSTACT_PARAMS| Standby Controller CCC Configuration RSTACT|
| 0x38 |            __rsvd_2            |                 Reserved 2                 |
| 0x3C |            __rsvd_3            |                 Reserved 3                 |

### EXTCAP_HEADER register

- Absolute Address: 0x180
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|   Name   |
|----|----------|------|-----|----------|
| 7:0|  CAP_ID  |   r  | 0x12|  CAP_ID  |
|23:8|CAP_LENGTH|   r  | 0x10|CAP_LENGTH|

#### CAP_ID field

<p>Extended Capability ID</p>

#### CAP_LENGTH field

<p>Capability Structure Length in DWORDs</p>

### STBY_CR_CONTROL register

- Absolute Address: 0x184
- Base Offset: 0x4
- Size: 0x4



| Bits|      Identifier     | Access |Reset|                       Name                       |
|-----|---------------------|--------|-----|--------------------------------------------------|
|  0  |   PENDING_RX_NACK   |   rw   |  —  |                  Pending RX NACK                 |
|  1  |  HANDOFF_DELAY_NACK |   rw   |  —  |                Handoff Delay NACK                |
|  2  |  ACR_FSM_OP_SELECT  |   rw   |  —  |             Active Controller Select             |
|  3  |PRIME_ACCEPT_GETACCCR|   rw   |  —  |          Prime to Accept Controller Role         |
|  4  |  HANDOFF_DEEP_SLEEP |rw, wset| 0x0 |                Handoff Deep Sleep                |
|  5  |   CR_REQUEST_SEND   |   rw   | 0x0 |           Send Controller Role Request           |
| 10:8|  BAST_CCC_IBI_RING  |   rw   | 0x0 |Ring Bundle IBI Selector for Broadcast CCC Capture|
|  12 |  TARGET_XACT_ENABLE |   rw   | 0x0 |   Target Transaction Interface Servicing Enable  |
|  13 |  DAA_SETAASA_ENABLE |   rw   | 0x0 |       Dynamic Address Method Enable SETAASA      |
|  14 |  DAA_SETDASA_ENABLE |   rw   | 0x0 |       Dynamic Address Method Enable SETDASA      |
|  15 |  DAA_ENTDAA_ENABLE  |   rw   | 0x0 |       Dynamic Address Method Enable ENTDAA       |
|  20 |  RSTACT_DEFBYTE_02  |   rw   | 0x0 |            RSTACT Support DefByte 0x02           |
|31:30| STBY_CR_ENABLE_INIT |   rw   | 0x0 |    Host Controller Secondary Controller Enable   |

#### PENDING_RX_NACK field



#### HANDOFF_DELAY_NACK field



#### ACR_FSM_OP_SELECT field



#### PRIME_ACCEPT_GETACCCR field



#### HANDOFF_DEEP_SLEEP field

<p>If this field has a value of 1'b1, then the Secondary Controller Logic shall
report a return from Deep Sleep state to the Active Controller.
Writing 1'b1 to this bit is sticky. This field shall automatically clear to 1'b0
after accepting the Controller Role and transitioning to Active Controller mode.</p>

#### CR_REQUEST_SEND field

<p>Write of 1'b1 to this field shall instruct the Secondary Controller Logic
to attempt to send a Controller Role Request to the I3C Bus.</p>

#### BAST_CCC_IBI_RING field

<p>Indicates which Ring Bundle will be used to capture Broadcast CCC data sent by the Active Controller.
The Ring Bundle must be configured and enabled, and its IBI Ring Pair must also be initialized and ready to receive data.</p>

#### TARGET_XACT_ENABLE field

<p>Indicates whether Read-Type/Write-Type transaction servicing is enabled, via
an I3C Target Transaction Interface to software (Section 6.17.3).</p>
<p>1'b0: DISABLED: not available</p>
<p>1'b1: ENABLED: available for software</p>

#### DAA_SETAASA_ENABLE field

<p>Indicates SETAASA method is enabled.</p>
<p>1'b0: DISABLED: will not respond</p>
<p>1'b1: ENABLED: will respond</p>

#### DAA_SETDASA_ENABLE field

<p>Indicates SETDASA method is enabled.</p>
<p>1'b0: DISABLED: will not respond</p>
<p>1'b1: ENABLED: will respond</p>

#### DAA_ENTDAA_ENABLE field

<p>Indicates ENTDAA method is enabled.</p>
<p>1'b0: DISABLED: will not respond</p>
<p>1'b1: ENABLED: will respond</p>

#### RSTACT_DEFBYTE_02 field

<p>Controls whether I3C Secondary Controller Logic supports RSTACT CCC with
Defining Byte 0x02.</p>
<p>1'b0: NOT_SUPPORTED: Do not ACK Defining Byte 0x02</p>
<p>1'b1: HANDLE_INTR: Support Defining Byte 0x02</p>

#### STBY_CR_ENABLE_INIT field

<p>Enables or disables the Secondary Controller:</p>
<p>2'b00 - DISABLED: Secondary Controller is disabled.</p>
<p>2'b01 - ACM_INIT: Secondary Controller is enabled,
but Host Controller initializes in Active Controller mode.</p>
<p>2'b10 - SCM_RUNNING: Secondary Controller operation is enabled,
Host Controller initializes in Standby Controller mode.</p>
<p>2'b11 - SCM_HOT_JOIN: Secondary Controller operation is enabled,
Host Controller conditionally becomes a Hot-Joining Device
to receive its Dynamic Address before operating in Standby Controller mode.</p>

### STBY_CR_DEVICE_ADDR register

- Absolute Address: 0x188
- Base Offset: 0x8
- Size: 0x4



| Bits|    Identifier    |Access|Reset|          Name          |
|-----|------------------|------|-----|------------------------|
| 6:0 |    STATIC_ADDR   |  rw  |  —  |  Device Static Address |
|  15 | STATIC_ADDR_VALID|  rw  |  —  | Static Address is Valid|
|22:16|   DYNAMIC_ADDR   |  rw  |  —  | Device Dynamic Address |
|  31 |DYNAMIC_ADDR_VALID|  rw  |  —  |Dynamic Address is Valid|

#### STATIC_ADDR field

<p>This field contains the Host Controller Device’s Static Address.</p>

#### STATIC_ADDR_VALID field

<p>Indicates whether or not the value in the STATIC_ADDR field is valid.</p>
<p>1'b0: The Static Address field is not valid</p>
<p>1'b1: The Static Address field is valid</p>

#### DYNAMIC_ADDR field

<p>Contains the Host Controller Device’s Dynamic Address.</p>

#### DYNAMIC_ADDR_VALID field

<p>Indicates whether or not the value in the DYNAMIC_ADDR field is valid.
1'b0: DYNAMIC_ADDR field is not valid
1'b1: DYNAMIC_ADDR field is valid</p>

### STBY_CR_CAPABILITIES register

- Absolute Address: 0x18C
- Base Offset: 0xC
- Size: 0x4



|Bits|     Identifier    |Access|Reset|        Name       |
|----|-------------------|------|-----|-------------------|
|  5 | SIMPLE_CRR_SUPPORT|  rw  |  —  | SIMPLE_CRR_SUPPORT|
| 12 |TARGET_XACT_SUPPORT|  rw  | 0x1 |TARGET_XACT_SUPPORT|
| 13 |DAA_SETAASA_SUPPORT|  rw  | 0x1 |DAA_SETAASA_SUPPORT|
| 14 |DAA_SETDASA_SUPPORT|  rw  | 0x1 |DAA_SETDASA_SUPPORT|
| 15 | DAA_ENTDAA_SUPPORT|  rw  | 0x1 | DAA_ENTDAA_SUPPORT|

#### SIMPLE_CRR_SUPPORT field



#### TARGET_XACT_SUPPORT field

<p>Defines whether an I3C Target Transaction Interface is supported.</p>
<p>1'b0: DISABLED: Not supported</p>
<p>1'b1: ENABLED: Supported via vendor-defined Extended Capability structure</p>

#### DAA_SETAASA_SUPPORT field

<p>Defines whether Dynamic Address Assignment with SETAASA CCC (using Static Address) is supported.</p>
<p>1'b0: DISABLED: Not supported</p>
<p>1'b1: ENABLED: Supported</p>

#### DAA_SETDASA_SUPPORT field

<p>Defines whether Dynamic Address Assignment with SETDASA CCC (using Static Address) is supported.</p>
<p>1'b0: DISABLED: Not supported</p>
<p>1'b1: ENABLED: Supported</p>

#### DAA_ENTDAA_SUPPORT field

<p>Defines whether Dynamic Address Assignment with ENTDAA CCC is supported.</p>
<p>1'b0: DISABLED: Not supported</p>
<p>1'b1: ENABLED: Supported</p>

### __rsvd_0 register

- Absolute Address: 0x190
- Base Offset: 0x10
- Size: 0x4



|Bits|Identifier|Access|Reset|  Name  |
|----|----------|------|-----|--------|
|31:0|  __rsvd  |  rw  |  —  |Reserved|

#### __rsvd field



### STBY_CR_STATUS register

- Absolute Address: 0x194
- Base Offset: 0x14
- Size: 0x4



|Bits|    Identifier   |Access|Reset|       Name      |
|----|-----------------|------|-----|-----------------|
|  2 |  AC_CURRENT_OWN |  rw  |  —  |  AC_CURRENT_OWN |
| 7:5|SIMPLE_CRR_STATUS|  rw  |  —  |SIMPLE_CRR_STATUS|
|  8 |  HJ_REQ_STATUS  |  rw  |  —  |  HJ_REQ_STATUS  |

#### AC_CURRENT_OWN field



#### SIMPLE_CRR_STATUS field



#### HJ_REQ_STATUS field



### STBY_CR_DEVICE_CHAR register

- Absolute Address: 0x198
- Base Offset: 0x18
- Size: 0x4



| Bits|Identifier|Access|Reset|   Name  |
|-----|----------|------|-----|---------|
| 15:1|  PID_HI  |  rw  |  —  |  PID_HI |
|23:16|    DCR   |  rw  |  —  |   DCR   |
|28:24|  BCR_VAR |  rw  |  —  | BCR_VAR |
|31:29| BCR_FIXED|  rw  |  —  |BCR_FIXED|

#### PID_HI field



#### DCR field



#### BCR_VAR field



#### BCR_FIXED field



### STBY_CR_DEVICE_PID_LO register

- Absolute Address: 0x19C
- Base Offset: 0x1C
- Size: 0x4



|Bits|Identifier|Access|Reset| Name |
|----|----------|------|-----|------|
|31:0|  PID_LO  |  rw  |  —  |PID_LO|

#### PID_LO field



### STBY_CR_INTR_STATUS register

- Absolute Address: 0x1A0
- Base Offset: 0x20
- Size: 0x4



|Bits|        Identifier        |Access|Reset|Name|
|----|--------------------------|------|-----|----|
|  0 |ACR_HANDOFF_OK_REMAIN_STAT|  rw  |  —  |    |
|  1 |ACR_HANDOFF_OK_PRIMED_STAT|  rw  |  —  |    |
|  2 | ACR_HANDOFF_ERR_FAIL_STAT|  rw  |  —  |    |
|  3 |  ACR_HANDOFF_ERR_M3_STAT |  rw  |  —  |    |
| 10 |     CRR_RESPONSE_STAT    |  rw  |  —  |    |
| 11 |   STBY_CR_DYN_ADDR_STAT  |  rw  |  —  |    |
| 12 |STBY_CR_ACCEPT_NACKED_STAT|  rw  |  —  |    |
| 13 |  STBY_CR_ACCEPT_OK_STAT  |  rw  |  —  |    |
| 14 |  STBY_CR_ACCEPT_ERR_STAT |  rw  |  —  |    |
| 16 |  STBY_CR_OP_RSTACT_STAT  |  rw  |  —  |    |
| 17 |  CCC_PARAM_MODIFIED_STAT |  rw  |  —  |    |
| 18 |  CCC_UNHANDLED_NACK_STAT |  rw  |  —  |    |
| 19 | CCC_FATAL_RSTDAA_ERR_STAT|  rw  |  —  |    |

#### ACR_HANDOFF_OK_REMAIN_STAT field



#### ACR_HANDOFF_OK_PRIMED_STAT field



#### ACR_HANDOFF_ERR_FAIL_STAT field



#### ACR_HANDOFF_ERR_M3_STAT field



#### CRR_RESPONSE_STAT field



#### STBY_CR_DYN_ADDR_STAT field



#### STBY_CR_ACCEPT_NACKED_STAT field



#### STBY_CR_ACCEPT_OK_STAT field



#### STBY_CR_ACCEPT_ERR_STAT field



#### STBY_CR_OP_RSTACT_STAT field



#### CCC_PARAM_MODIFIED_STAT field



#### CCC_UNHANDLED_NACK_STAT field



#### CCC_FATAL_RSTDAA_ERR_STAT field



### __rsvd_1 register

- Absolute Address: 0x1A4
- Base Offset: 0x24
- Size: 0x4



|Bits|Identifier|Access|Reset|  Name  |
|----|----------|------|-----|--------|
|31:0|  __rsvd  |  rw  |  —  |Reserved|

#### __rsvd field



### STBY_CR_INTR_SIGNAL_ENABLE register

- Absolute Address: 0x1A8
- Base Offset: 0x28
- Size: 0x4



|Bits|           Identifier          |Access|Reset|Name|
|----|-------------------------------|------|-----|----|
|  0 |ACR_HANDOFF_OK_REMAIN_SIGNAL_EN|  rw  |  —  |    |
|  1 |ACR_HANDOFF_OK_PRIMED_SIGNAL_EN|  rw  |  —  |    |
|  2 | ACR_HANDOFF_ERR_FAIL_SIGNAL_EN|  rw  |  —  |    |
|  3 |  ACR_HANDOFF_ERR_M3_SIGNAL_EN |  rw  |  —  |    |
| 10 |     CRR_RESPONSE_SIGNAL_EN    |  rw  |  —  |    |
| 11 |   STBY_CR_DYN_ADDR_SIGNAL_EN  |  rw  |  —  |    |
| 12 |STBY_CR_ACCEPT_NACKED_SIGNAL_EN|  rw  |  —  |    |
| 13 |  STBY_CR_ACCEPT_OK_SIGNAL_EN  |  rw  |  —  |    |
| 14 |  STBY_CR_ACCEPT_ERR_SIGNAL_EN |  rw  |  —  |    |
| 16 |  STBY_CR_OP_RSTACT_SIGNAL_EN  |  rw  |  —  |    |
| 17 |  CCC_PARAM_MODIFIED_SIGNAL_EN |  rw  |  —  |    |
| 18 |  CCC_UNHANDLED_NACK_SIGNAL_EN |  rw  |  —  |    |
| 19 | CCC_FATAL_RSTDAA_ERR_SIGNAL_EN|  rw  |  —  |    |

#### ACR_HANDOFF_OK_REMAIN_SIGNAL_EN field



#### ACR_HANDOFF_OK_PRIMED_SIGNAL_EN field



#### ACR_HANDOFF_ERR_FAIL_SIGNAL_EN field



#### ACR_HANDOFF_ERR_M3_SIGNAL_EN field



#### CRR_RESPONSE_SIGNAL_EN field



#### STBY_CR_DYN_ADDR_SIGNAL_EN field



#### STBY_CR_ACCEPT_NACKED_SIGNAL_EN field



#### STBY_CR_ACCEPT_OK_SIGNAL_EN field



#### STBY_CR_ACCEPT_ERR_SIGNAL_EN field



#### STBY_CR_OP_RSTACT_SIGNAL_EN field



#### CCC_PARAM_MODIFIED_SIGNAL_EN field



#### CCC_UNHANDLED_NACK_SIGNAL_EN field



#### CCC_FATAL_RSTDAA_ERR_SIGNAL_EN field



### STBY_CR_INTR_FORCE register

- Absolute Address: 0x1AC
- Base Offset: 0x2C
- Size: 0x4



|Bits|         Identifier        |Access|Reset|Name|
|----|---------------------------|------|-----|----|
| 10 |     CRR_RESPONSE_FORCE    |  rw  |  —  |    |
| 11 |   STBY_CR_DYN_ADDR_FORCE  |  rw  |  —  |    |
| 12 |STBY_CR_ACCEPT_NACKED_FORCE|  rw  |  —  |    |
| 13 |  STBY_CR_ACCEPT_OK_FORCE  |  rw  |  —  |    |
| 14 |  STBY_CR_ACCEPT_ERR_FORCE |  rw  |  —  |    |
| 16 |  STBY_CR_OP_RSTACT_FORCE  |  rw  |  —  |    |
| 17 |  CCC_PARAM_MODIFIED_FORCE |  rw  |  —  |    |
| 18 |  CCC_UNHANDLED_NACK_FORCE |  rw  |  —  |    |
| 19 | CCC_FATAL_RSTDAA_ERR_FORCE|  rw  |  —  |    |

#### CRR_RESPONSE_FORCE field



#### STBY_CR_DYN_ADDR_FORCE field



#### STBY_CR_ACCEPT_NACKED_FORCE field



#### STBY_CR_ACCEPT_OK_FORCE field



#### STBY_CR_ACCEPT_ERR_FORCE field



#### STBY_CR_OP_RSTACT_FORCE field



#### CCC_PARAM_MODIFIED_FORCE field



#### CCC_UNHANDLED_NACK_FORCE field



#### CCC_FATAL_RSTDAA_ERR_FORCE field



### STBY_CR_CCC_CONFIG_GETCAPS register

- Absolute Address: 0x1B0
- Base Offset: 0x30
- Size: 0x4



|Bits|      Identifier      |Access|Reset|Name|
|----|----------------------|------|-----|----|
| 2:0| F2_CRCAP1_BUS_CONFIG |  rw  |  —  |    |
|11:8|F2_CRCAP2_DEV_INTERACT|  rw  |  —  |    |

#### F2_CRCAP1_BUS_CONFIG field



#### F2_CRCAP2_DEV_INTERACT field



### STBY_CR_CCC_CONFIG_RSTACT_PARAMS register

- Absolute Address: 0x1B4
- Base Offset: 0x34
- Size: 0x4



| Bits|      Identifier     |Access|Reset|Name|
|-----|---------------------|------|-----|----|
| 7:0 |      RST_ACTION     |  rw  |  —  |    |
| 15:8|RESET_TIME_PERIPHERAL|  rw  |  —  |    |
|23:16|  RESET_TIME_TARGET  |  rw  |  —  |    |
|  31 |  RESET_DYNAMIC_ADDR |  rw  |  —  |    |

#### RST_ACTION field



#### RESET_TIME_PERIPHERAL field



#### RESET_TIME_TARGET field



#### RESET_DYNAMIC_ADDR field



### __rsvd_2 register

- Absolute Address: 0x1B8
- Base Offset: 0x38
- Size: 0x4



|Bits|Identifier|Access|Reset|  Name  |
|----|----------|------|-----|--------|
|31:0|  __rsvd  |  rw  |  —  |Reserved|

#### __rsvd field



### __rsvd_3 register

- Absolute Address: 0x1BC
- Base Offset: 0x3C
- Size: 0x4



|Bits|Identifier|Access|Reset|  Name  |
|----|----------|------|-----|--------|
|31:0|  __rsvd  |  rw  |  —  |Reserved|

#### __rsvd field



## TTI register file

- Absolute Address: 0x1C0
- Base Offset: 0xC0
- Size: 0x40

|Offset|      Identifier     |              Name             |
|------|---------------------|-------------------------------|
| 0x00 |    EXTCAP_HEADER    |               —               |
| 0x04 |       CONTROL       |          TTI Control          |
| 0x08 |        STATUS       |           TTI Status          |
| 0x0C |    RESET_CONTROL    |    TTI Queue Reset Control    |
| 0x10 |   INTERRUPT_STATUS  |      TTI Interrupt Status     |
| 0x14 |   INTERRUPT_ENABLE  |      TTI Interrupt Enable     |
| 0x18 |   INTERRUPT_FORCE   |      TTI Interrupt Force      |
| 0x1C |  RX_DESC_QUEUE_PORT |  TTI RX Descriptor Queue Port |
| 0x20 |     RX_DATA_PORT    |        TTI RX Data Port       |
| 0x24 |  TX_DESC_QUEUE_PORT |  TTI TX Descriptor Queue Port |
| 0x28 |     TX_DATA_PORT    |        TTI TX Data Port       |
| 0x2C |       IBI_PORT      |       TTI IBI Data Port       |
| 0x30 |      QUEUE_SIZE     |         TTI Queue Size        |
| 0x34 |    IBI_QUEUE_SIZE   |       TTI IBI Queue Size      |
| 0x38 |   QUEUE_THLD_CTRL   |  TTI Queue Threshold Control  |
| 0x3C |DATA_BUFFER_THLD_CTRL|TTI IBI Queue Threshold Control|

### EXTCAP_HEADER register

- Absolute Address: 0x1C0
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|   Name   |
|----|----------|------|-----|----------|
| 7:0|  CAP_ID  |   r  | 0xC4|  CAP_ID  |
|23:8|CAP_LENGTH|   r  | 0x10|CAP_LENGTH|

#### CAP_ID field

<p>Extended Capability ID</p>

#### CAP_LENGTH field

<p>Capability Structure Length in DWORDs</p>

### CONTROL register

- Absolute Address: 0x1C4
- Base Offset: 0x4
- Size: 0x4

<p>Control Register</p>

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### STATUS register

- Absolute Address: 0x1C8
- Base Offset: 0x8
- Size: 0x4

<p>Status Register</p>

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### RESET_CONTROL register

- Absolute Address: 0x1CC
- Base Offset: 0xC
- Size: 0x4

<p>Queue Reset Control</p>

|Bits|  Identifier |Access|Reset|     Name    |
|----|-------------|------|-----|-------------|
|  0 |   SOFT_RST  |  rw  | 0x0 |   SOFT_RST  |
|  1 | TX_DESC_RST |  rw  | 0x0 | TX_DESC_RST |
|  2 | RX_DESC_RST |  rw  | 0x0 | RX_DESC_RST |
|  3 | TX_DATA_RST |  rw  | 0x0 | TX_DATA_RST |
|  4 | RX_DATA_RST |  rw  | 0x0 | RX_DATA_RST |
|  5 |IBI_QUEUE_RST|  rw  | 0x0 |IBI_QUEUE_RST|

#### SOFT_RST field

<p>Target Core Software Reset</p>

#### TX_DESC_RST field

<p>TTI TX Descriptor Queue Buffer Software Reset</p>

#### RX_DESC_RST field

<p>TTI RX Descriptor Queue Buffer Software Reset</p>

#### TX_DATA_RST field

<p>TTI TX Data Queue Buffer Software Reset</p>

#### RX_DATA_RST field

<p>TTI RX Data Queue Buffer Software Reset</p>

#### IBI_QUEUE_RST field

<p>TTI IBI Queue Buffer Software Reset</p>

### INTERRUPT_STATUS register

- Absolute Address: 0x1D0
- Base Offset: 0x10
- Size: 0x4

<p>Interrupt Status</p>

|Bits|     Identifier    |  Access |Reset|        Name       |
|----|-------------------|---------|-----|-------------------|
|  0 |    RX_DESC_STAT   |rw, woclr| 0x0 |    RX_DESC_STAT   |
|  1 |    TX_DESC_STAT   |rw, woclr| 0x0 |    TX_DESC_STAT   |
|  2 |  RX_DESC_TIMEOUT  |rw, woclr| 0x0 |  RX_DESC_TIMEOUT  |
|  3 |  TX_DESC_TIMEOUT  |rw, woclr| 0x0 |  TX_DESC_TIMEOUT  |
|  8 | TX_DATA_THLD_STAT |    r    | 0x0 | TX_DATA_THLD_STAT |
|  9 | RX_DATA_THLD_STAT |    r    | 0x0 | RX_DATA_THLD_STAT |
| 10 | TX_DESC_THLD_STAT |    r    | 0x0 | TX_DESC_THLD_STAT |
| 11 | RX_DESC_THLD_STAT |    r    | 0x0 | RX_DESC_THLD_STAT |
| 12 |   IBI_THLD_STAT   |    r    | 0x0 |   IBI_THLD_STAT   |
| 25 |TRANSFER_ABORT_STAT|rw, woclr| 0x0 |TRANSFER_ABORT_STAT|
| 31 | TRANSFER_ERR_STAT |rw, woclr| 0x0 | TRANSFER_ERR_STAT |

#### RX_DESC_STAT field

<p>There is a pending Read Transaction. Software should read data from the RX Descriptor Queue and the RX Data Queue</p>

#### TX_DESC_STAT field

<p>There is a pending Write Transaction on the I3C Bus. Software should write data to the TX Descriptor Queue and the TX Data Queue</p>

#### RX_DESC_TIMEOUT field

<p>Pending Read was NACK’ed, because the <code>RX_DESC_STAT</code> event was not handled in time</p>

#### TX_DESC_TIMEOUT field

<p>Pending Write was NACK’ed, because the <code>TX_DESC_STAT</code> event was not handled in time</p>

#### TX_DATA_THLD_STAT field

<p>TTI TX Data Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI TX Data Queue is &gt;= the value defined in <code>TTI_TX_DATA_THLD</code></p>

#### RX_DATA_THLD_STAT field

<p>TTI RX Data Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of entries in the TTI RX Data Queue is &gt;= the value defined in <code>TTI_RX_DATA_THLD</code></p>

#### TX_DESC_THLD_STAT field

<p>TTI TX Descriptor Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI TX Descriptor Queue is &gt;= the value defined in <code>TTI_TX_DESC_THLD</code></p>

#### RX_DESC_THLD_STAT field

<p>TTI RX Descriptor Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI RX Descriptor Queue is &gt;= the value defined in <code>TTI_RX_DESC_THLD</code></p>

#### IBI_THLD_STAT field

<p>TTI IBI Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI IBI Queue is &gt;= the value defined in <code>TTI_IBI_THLD</code></p>

#### TRANSFER_ABORT_STAT field

<p>Bus aborted transaction</p>

#### TRANSFER_ERR_STAT field

<p>Bus error occurred</p>

### INTERRUPT_ENABLE register

- Absolute Address: 0x1D4
- Base Offset: 0x14
- Size: 0x4

<p>Interrupt Enable</p>

|Bits|     Identifier     |Access|Reset|        Name        |
|----|--------------------|------|-----|--------------------|
|  0 |TX_DATA_THLD_STAT_EN|  rw  | 0x0 |TX_DATA_THLD_STAT_EN|
|  1 |RX_DATA_THLD_STAT_EN|  rw  | 0x0 |RX_DATA_THLD_STAT_EN|
|  2 |TX_DESC_THLD_STAT_EN|  rw  | 0x0 |TX_DESC_THLD_STAT_EN|
|  3 |RX_DESC_THLD_STAT_EN|  rw  | 0x0 |RX_DESC_THLD_STAT_EN|
|  4 |  IBI_THLD_STAT_EN  |  rw  | 0x0 |  IBI_THLD_STAT_EN  |

#### TX_DATA_THLD_STAT_EN field

<p>Enables the corresponding interrupt bit <code>TTI_TX_DATA_THLD_STAT</code></p>

#### RX_DATA_THLD_STAT_EN field

<p>Enables the corresponding interrupt bit <code>TTI_RX_DATA_THLD_STAT</code></p>

#### TX_DESC_THLD_STAT_EN field

<p>Enables the corresponding interrupt bit <code>TTI_TX_DESC_THLD_STAT</code></p>

#### RX_DESC_THLD_STAT_EN field

<p>Enables the corresponding interrupt bit <code>TTI_RX_DESC_THLD_STAT</code></p>

#### IBI_THLD_STAT_EN field

<p>Enables the corresponding interrupt bit <code>TTI_IBI_THLD_STAT</code></p>

### INTERRUPT_FORCE register

- Absolute Address: 0x1D8
- Base Offset: 0x18
- Size: 0x4

<p>Interrupt Force</p>

|Bits|    Identifier    |Access|Reset|       Name       |
|----|------------------|------|-----|------------------|
|  0 |TX_DATA_THLD_FORCE|  rw  | 0x0 |TX_DATA_THLD_FORCE|
|  1 |RX_DATA_THLD_FORCE|  rw  | 0x0 |RX_DATA_THLD_FORCE|
|  2 |TX_DESC_THLD_FORCE|  rw  | 0x0 |TX_DESC_THLD_FORCE|
|  3 |RX_DESC_THLD_FORCE|  rw  | 0x0 |RX_DESC_THLD_FORCE|
|  4 |  IBI_THLD_FORCE  |  rw  | 0x0 |  IBI_THLD_FORCE  |

#### TX_DATA_THLD_FORCE field

<p>Forces the corresponding interrupt bit <code>TTI_TX_DATA_THLD_STAT</code> to be set to <code>1</code></p>

#### RX_DATA_THLD_FORCE field

<p>Forces the corresponding interrupt bit <code>TTI_RX_DATA_THLD_STAT</code> to be set to <code>1</code></p>

#### TX_DESC_THLD_FORCE field

<p>Forces the corresponding interrupt bit <code>TTI_TX_DESC_THLD_STAT</code> to be set to <code>1</code></p>

#### RX_DESC_THLD_FORCE field

<p>Forces the corresponding interrupt bit <code>TTI_RX_DESC_THLD_STAT</code> to be set to <code>1</code></p>

#### IBI_THLD_FORCE field

<p>Forces the corresponding interrupt bit <code>TTI_IBI_THLD_STAT</code> to be set to 1</p>

### RX_DESC_QUEUE_PORT register

- Absolute Address: 0x1DC
- Base Offset: 0x1C
- Size: 0x4

<p>RX Descriptor Queue Port</p>

|Bits|Identifier|Access|Reset|  Name |
|----|----------|------|-----|-------|
|31:0|  RX_DESC |   r  | 0x0 |RX_DESC|

#### RX_DESC field

<p>RX Data</p>

### RX_DATA_PORT register

- Absolute Address: 0x1E0
- Base Offset: 0x20
- Size: 0x4

<p>RX Data Port</p>

|Bits|Identifier|Access|Reset|  Name |
|----|----------|------|-----|-------|
|31:0|  RX_DATA |   r  | 0x0 |RX_DATA|

#### RX_DATA field

<p>RX Data</p>

### TX_DESC_QUEUE_PORT register

- Absolute Address: 0x1E4
- Base Offset: 0x24
- Size: 0x4

<p>TX Descriptor Queue Port</p>

|Bits|Identifier|Access|Reset|  Name |
|----|----------|------|-----|-------|
|31:0|  TX_DESC |   w  | 0x0 |TX_DESC|

#### TX_DESC field

<p>TX Data</p>

### TX_DATA_PORT register

- Absolute Address: 0x1E8
- Base Offset: 0x28
- Size: 0x4

<p>TX Data Port</p>

|Bits|Identifier|Access|Reset|  Name |
|----|----------|------|-----|-------|
|31:0|  TX_DATA |   w  | 0x0 |TX_DATA|

#### TX_DATA field

<p>TX Data</p>

### IBI_PORT register

- Absolute Address: 0x1EC
- Base Offset: 0x2C
- Size: 0x4

<p>IBI Data Port</p>

|Bits|Identifier|Access|Reset|  Name  |
|----|----------|------|-----|--------|
|31:0| IBI_DATA |   w  | 0x0 |IBI_DATA|

#### IBI_DATA field

<p>IBI Data</p>

### QUEUE_SIZE register

- Absolute Address: 0x1F0
- Base Offset: 0x30
- Size: 0x4

<p>Queue Size</p>

| Bits|     Identifier    |Access|Reset|        Name       |
|-----|-------------------|------|-----|-------------------|
| 7:0 |RX_DESC_BUFFER_SIZE|   r  | 0x5 |RX_DESC_BUFFER_SIZE|
| 15:8|TX_DESC_BUFFER_SIZE|   r  | 0x5 |TX_DESC_BUFFER_SIZE|
|23:16|RX_DATA_BUFFER_SIZE|   r  | 0x5 |RX_DATA_BUFFER_SIZE|
|31:24|TX_DATA_BUFFER_SIZE|   r  | 0x5 |TX_DATA_BUFFER_SIZE|

#### RX_DESC_BUFFER_SIZE field

<p>RX Descriptor Buffer Size in DWORDs calculated as <code>2^(N+1)</code></p>

#### TX_DESC_BUFFER_SIZE field

<p>TX Descriptor Buffer Size in DWORDs calculated as <code>2^(N+1)</code></p>

#### RX_DATA_BUFFER_SIZE field

<p>Receive Data Buffer Size in DWORDs calculated as <code>2^(N+1)</code></p>

#### TX_DATA_BUFFER_SIZE field

<p>Transmit Data Buffer Size in DWORDs calculated as <code>2^(N+1)</code></p>

### IBI_QUEUE_SIZE register

- Absolute Address: 0x1F4
- Base Offset: 0x34
- Size: 0x4

<p>IBI Queue Size</p>

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
| 7:0|IBI_QUEUE_SIZE|   r  | 0x5 |IBI_QUEUE_SIZE|

#### IBI_QUEUE_SIZE field

<p>IBI Queue Size in DWORDs calculated as <code>2^(N+1)</code></p>

### QUEUE_THLD_CTRL register

- Absolute Address: 0x1F8
- Base Offset: 0x38
- Size: 0x4

<p>Queue Threshold Control</p>

| Bits| Identifier |Access|Reset|    Name    |
|-----|------------|------|-----|------------|
| 7:0 |TX_DESC_THLD|  rw  | 0x1 |TX_DESC_THLD|
| 15:8|RX_DESC_THLD|  rw  | 0x1 |RX_DESC_THLD|
|31:24|  IBI_THLD  |  rw  | 0x1 |  IBI_THLD  |

#### TX_DESC_THLD field

<p>Controls the minimum number of empty TTI TX Descriptor Queue entries needed to trigger the TTI TX Descriptor interrupt.</p>

#### RX_DESC_THLD field

<p>Controls the minimum number of TTI RX Descriptor Queue entries needed to trigger the TTI RX Descriptor interrupt.</p>

#### IBI_THLD field

<p>Controls the minimum number of IBI Queue entries needed to trigger the IBI threshold interrupt.</p>

### DATA_BUFFER_THLD_CTRL register

- Absolute Address: 0x1FC
- Base Offset: 0x3C
- Size: 0x4

<p>IBI Queue Threshold Control</p>

| Bits|  Identifier |Access|Reset|    Name    |
|-----|-------------|------|-----|------------|
| 2:0 | TX_DATA_THLD|  rw  | 0x1 |TX_DATA_THLD|
| 10:8| RX_DATA_THLD|  rw  | 0x1 |RX_DATA_THLD|
|18:16|TX_START_THLD|  rw  | 0x1 |TX_DATA_THLD|
|26:24|RX_START_THLD|  rw  | 0x1 |RX_DATA_THLD|

#### TX_DATA_THLD field

<p>Minimum number of available TTI TX Data queue entries, in DWORDs, that will trigger the TTI TX Data interrupt. Interrupt triggers when <code>2^(N+1)</code> TX Buffer DWORD entries are available.</p>

#### RX_DATA_THLD field

<p>Minimum number of TTI RX Data queue entries of data received, in DWORDs, that will trigger the TTI RX Data interrupt. Interrupt triggers when <code>2^(N+1)</code> RX Buffer DWORD entries are received during the Read transfer.</p>

#### TX_START_THLD field

<p>Minimum number of available TTI TX Data queue entries, in DWORDs, that will trigger the TTI TX Data interrupt. Interrupt triggers when <code>2^(N+1)</code> TX Buffer DWORD entries are available.</p>

#### RX_START_THLD field

<p>Minimum number of TTI RX Data queue entries of data received, in DWORDs, that will trigger the TTI RX Data interrupt. Interrupt triggers when <code>2^(N+1)</code> RX Buffer DWORD entries are received during the Read transfer.</p>

## SoCMgmtIf register file

- Absolute Address: 0x200
- Base Offset: 0x100
- Size: 0x5C

|Offset|    Identifier    |                  Name                  |
|------|------------------|----------------------------------------|
| 0x00 |   EXTCAP_HEADER  |                    —                   |
| 0x04 | SOC_MGMT_CONTROL |         SoC Management Control         |
| 0x08 |  SOC_MGMT_STATUS |          SoC Management Status         |
| 0x0C |  SOC_MGMT_RSVD_0 |                                        |
| 0x10 |  SOC_MGMT_RSVD_1 |                                        |
| 0x14 |  SOC_MGMT_RSVD_2 |                                        |
| 0x18 |  SOC_MGMT_RSVD_3 |                                        |
| 0x1C |   SOC_PAD_CONF   |     I3C Pad Configuration Register     |
| 0x20 |   SOC_PAD_ATTR   |I3C Pad Attribute Configuration Register|
| 0x24 |SOC_MGMT_FEATURE_2|                                        |
| 0x28 |SOC_MGMT_FEATURE_3|                                        |
| 0x2C |      T_R_REG     |                                        |
| 0x30 |      T_F_REG     |                                        |
| 0x34 |   T_SU_DAT_REG   |                                        |
| 0x38 |   T_HD_DAT_REG   |                                        |
| 0x3C |    T_HIGH_REG    |                                        |
| 0x40 |     T_LOW_REG    |                                        |
| 0x44 |   T_HD_STA_REG   |                                        |
| 0x48 |   T_SU_STA_REG   |                                        |
| 0x4C |   T_SU_STO_REG   |                                        |
| 0x50 |    T_FREE_REG    |                                        |
| 0x54 |    T_AVAL_REG    |                                        |
| 0x58 |    T_IDLE_REG    |                                        |

### EXTCAP_HEADER register

- Absolute Address: 0x200
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|   Name   |
|----|----------|------|-----|----------|
| 7:0|  CAP_ID  |   r  | 0xC1|  CAP_ID  |
|23:8|CAP_LENGTH|   r  | 0x18|CAP_LENGTH|

#### CAP_ID field

<p>Extended Capability ID</p>

#### CAP_LENGTH field

<p>Capability Structure Length in DWORDs</p>

### SOC_MGMT_CONTROL register

- Absolute Address: 0x204
- Base Offset: 0x4
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### SOC_MGMT_STATUS register

- Absolute Address: 0x208
- Base Offset: 0x8
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### SOC_MGMT_RSVD_0 register

- Absolute Address: 0x20C
- Base Offset: 0xC
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### SOC_MGMT_RSVD_1 register

- Absolute Address: 0x210
- Base Offset: 0x10
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### SOC_MGMT_RSVD_2 register

- Absolute Address: 0x214
- Base Offset: 0x14
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### SOC_MGMT_RSVD_3 register

- Absolute Address: 0x218
- Base Offset: 0x18
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field



### SOC_PAD_CONF register

- Absolute Address: 0x21C
- Base Offset: 0x1C
- Size: 0x4

| Bits|  Identifier |Access|Reset|           Name          |
|-----|-------------|------|-----|-------------------------|
|  0  | INPUT_ENABLE|  rw  | 0x1 |       Enable Input      |
|  1  |  SCHMITT_EN |  rw  | 0x0 |  Schmitt Trigger Enable |
|  2  |  KEEPER_EN  |  rw  | 0x0 |    High-Keeper Enable   |
|  3  |   PULL_DIR  |  rw  | 0x0 |      Pull Direction     |
|  4  |   PULL_EN   |  rw  | 0x0 |       Pull Enable       |
|  5  | IO_INVERSION|  rw  | 0x0 |       IO INVERSION      |
|  6  |    OD_EN    |  rw  | 0x0 |    Open-Drain Enable    |
|  7  |VIRTUAL_OD_EN|  rw  | 0x0 |Virtual Open Drain Enable|
|31:24|   PAD_TYPE  |  rw  | 0x1 |         Pad type        |

#### INPUT_ENABLE field

<p>Enable input:</p>
<p>0 - enabled</p>
<p>1 - disabled</p>

#### SCHMITT_EN field

<p>Enable the Schmitt Trigger:</p>
<p>0 - disabled</p>
<p>1 - enabled</p>

#### KEEPER_EN field

<p>Enable the High-Keeper:</p>
<p>0 - disabled</p>
<p>1 - enabled</p>

#### PULL_DIR field

<p>Direction of the pull:</p>
<p>0 - Pull down</p>
<p>1 - Pull up</p>

#### PULL_EN field

<p>Enable Pull:</p>
<p>0 - disabled</p>
<p>1 - enabled</p>

#### IO_INVERSION field

<p>Invert I/O signal:</p>
<p>0 - signals pass-through</p>
<p>1 - signals are inverted</p>

#### OD_EN field

<p>Enable Open-Drain:</p>
<p>0 - disabled</p>
<p>1 - enabled</p>

#### VIRTUAL_OD_EN field

<p>Enable virtual open drain:</p>
<p>0 - disabled</p>
<p>1 - enabled</p>

#### PAD_TYPE field

<p>Select pad type</p>
<p>0 - Bidirectional</p>
<p>1 - Open-drain</p>
<p>2 - Input-only</p>
<p>3 - Analog input</p>

### SOC_PAD_ATTR register

- Absolute Address: 0x220
- Base Offset: 0x20
- Size: 0x4

| Bits|   Identifier  |Access|Reset|      Name      |
|-----|---------------|------|-----|----------------|
| 15:8|DRIVE_SLEW_RATE|  rw  | 0xF |Driver Slew Rate|
|31:24| DRIVE_STRENGTH|  rw  | 0xF | Driver Strength|

#### DRIVE_SLEW_RATE field

<p>Select driver slew rate</p>
<p>'0 - lowest</p>
<p>'1 - highest</p>

#### DRIVE_STRENGTH field

<p>Select driver strength</p>
<p>'0 - lowest</p>
<p>'1 - highest</p>

### SOC_MGMT_FEATURE_2 register

- Absolute Address: 0x224
- Base Offset: 0x24
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field

<p>Reserved for: I/O ring and pad configuration</p>

### SOC_MGMT_FEATURE_3 register

- Absolute Address: 0x228
- Base Offset: 0x28
- Size: 0x4

|Bits| Identifier|Access|Reset|Name|
|----|-----------|------|-----|----|
|31:0|PLACEHOLDER|  rw  | 0x0 |    |

#### PLACEHOLDER field

<p>Reserved for: I/O ring and pad configuration</p>

### T_R_REG register

- Absolute Address: 0x22C
- Base Offset: 0x2C
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0|    T_R   |  rw  | 0x0 |    |

#### T_R field

<p>Rise time of both SDA and SCL in clock units</p>

### T_F_REG register

- Absolute Address: 0x230
- Base Offset: 0x30
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0|    T_F   |  rw  | 0x0 |    |

#### T_F field

<p>Fall time of both SDA and SCL in clock units</p>

### T_SU_DAT_REG register

- Absolute Address: 0x234
- Base Offset: 0x34
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0| T_SU_DAT |  rw  | 0x0 |    |

#### T_SU_DAT field

<p>Data setup time in clock units</p>

### T_HD_DAT_REG register

- Absolute Address: 0x238
- Base Offset: 0x38
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0| T_HD_DAT |  rw  | 0x0 |    |

#### T_HD_DAT field

<p>Data hold time in clock units</p>

### T_HIGH_REG register

- Absolute Address: 0x23C
- Base Offset: 0x3C
- Size: 0x4

|Bits|Identifier|Access|Reset|                 Name                |
|----|----------|------|-----|-------------------------------------|
|19:0|  T_HIGH  |  rw  | 0x0 |High period of the SCL in clock units|

#### T_HIGH field



### T_LOW_REG register

- Absolute Address: 0x240
- Base Offset: 0x40
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0|   T_LOW  |  rw  | 0x0 |    |

#### T_LOW field

<p>Low period of the SCL in clock units</p>

### T_HD_STA_REG register

- Absolute Address: 0x244
- Base Offset: 0x44
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0| T_HD_STA |  rw  | 0x0 |    |

#### T_HD_STA field

<p>Hold time for (repeated) START in clock units</p>

### T_SU_STA_REG register

- Absolute Address: 0x248
- Base Offset: 0x48
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0| T_SU_STA |  rw  | 0x0 |    |

#### T_SU_STA field

<p>Setup time for repeated START in clock units</p>

### T_SU_STO_REG register

- Absolute Address: 0x24C
- Base Offset: 0x4C
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|19:0| T_SU_STO |  rw  | 0x0 |    |

#### T_SU_STO field

<p>Setup time for STOP in clock units</p>

### T_FREE_REG register

- Absolute Address: 0x250
- Base Offset: 0x50
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  T_FREE  |  rw  | 0xC |    |

#### T_FREE field



### T_AVAL_REG register

- Absolute Address: 0x254
- Base Offset: 0x54
- Size: 0x4

|Bits|Identifier|Access|Reset|Name|
|----|----------|------|-----|----|
|31:0|  T_AVAL  |  rw  |0x12C|    |

#### T_AVAL field



### T_IDLE_REG register

- Absolute Address: 0x258
- Base Offset: 0x58
- Size: 0x4

|Bits|Identifier|Access| Reset|Name|
|----|----------|------|------|----|
|31:0|  T_IDLE  |  rw  |0xEA60|    |

#### T_IDLE field



## CtrlCfg register file

- Absolute Address: 0x260
- Base Offset: 0x160
- Size: 0x8

|Offset|    Identifier   |       Name      |
|------|-----------------|-----------------|
|  0x0 |  EXTCAP_HEADER  |        —        |
|  0x4 |CONTROLLER_CONFIG|Controller Config|

### EXTCAP_HEADER register

- Absolute Address: 0x260
- Base Offset: 0x0
- Size: 0x4

|Bits|Identifier|Access|Reset|   Name   |
|----|----------|------|-----|----------|
| 7:0|  CAP_ID  |   r  | 0x2 |  CAP_ID  |
|23:8|CAP_LENGTH|   r  | 0x2 |CAP_LENGTH|

#### CAP_ID field

<p>Extended Capability ID</p>

#### CAP_LENGTH field

<p>Capability Structure Length in DWORDs</p>

### CONTROLLER_CONFIG register

- Absolute Address: 0x264
- Base Offset: 0x4
- Size: 0x4

|Bits|  Identifier  |Access|Reset|     Name     |
|----|--------------|------|-----|--------------|
| 5:4|OPERATION_MODE|   r  | 0x1 |Operation Mode|

#### OPERATION_MODE field



### TERMINATION_EXTCAP_HEADER register

- Absolute Address: 0x268
- Base Offset: 0x168
- Size: 0x4

<p>Register after the last EC must advertise ID == 0.
Termination register is added to guarantee that the discovery mechanism
reaches termination value.</p>

|Bits|Identifier|Access|Reset|   Name   |
|----|----------|------|-----|----------|
| 7:0|  CAP_ID  |   r  | 0x0 |  CAP_ID  |
|23:8|CAP_LENGTH|   r  | 0x1 |CAP_LENGTH|

#### CAP_ID field

<p>Extended Capability ID</p>

#### CAP_LENGTH field

<p>Capability Structure Length in DWORDs</p>

## DAT memory

- Absolute Address: 0x400
- Base Offset: 0x400
- Size: 0x400

|Offset|   Identifier  |Name|
|------|---------------|----|
|  0x0 |DAT_MEMORY[128]|  — |

### DAT_MEMORY register

- Absolute Address: 0x400
- Base Offset: 0x0
- Size: 0x400
- Array Dimensions: [128]
- Array Stride: 0x8
- Total Size: 0x400

| Bits|    Identifier    |Access|Reset|       Name       |
|-----|------------------|------|-----|------------------|
| 6:0 |  STATIC_ADDRESS  |  rw  |  —  |  STATIC_ADDRESS  |
|  12 |    IBI_PAYLOAD   |  rw  |  —  |    IBI_PAYLOAD   |
|  13 |    IBI_REJECT    |  rw  |  —  |    IBI_REJECT    |
|  14 |    CRR_REJECT    |  rw  |  —  |    CRR_REJECT    |
|  15 |        TS        |  rw  |  —  |        TS        |
|23:16|  DYNAMIC_ADDRESS |  rw  |  —  |  DYNAMIC_ADDRESS |
|28:26|      RING_ID     |  rw  |  —  |      RING_ID     |
|30:29|DEV_NACK_RETRY_CNT|  rw  |  —  |DEV_NACK_RETRY_CNT|
|  31 |      DEVICE      |  rw  |  —  |      DEVICE      |
|39:32|   AUTOCMD_MASK   |  rw  |  —  |   AUTOCMD_MASK   |
|47:40|   AUTOCMD_VALUE  |  rw  |  —  |   AUTOCMD_VALUE  |
|50:48|   AUTOCMD_MODE   |  rw  |  —  |   AUTOCMD_MODE   |
|58:51| AUTOCMD_HDR_CODE |  rw  |  —  | AUTOCMD_HDR_CODE |

#### STATIC_ADDRESS field

<p>I3C/I2C static device address</p>

#### IBI_PAYLOAD field

<p>Device's IBI contains data payload</p>

#### IBI_REJECT field

<p>Reject device's request for IBI</p>

#### CRR_REJECT field

<p>Reject device's request for controller change</p>

#### TS field

<p>Enable/disable IBI timestamp</p>

#### DYNAMIC_ADDRESS field

<p>I3C dynamic address</p>

#### RING_ID field

<p>Send IBI read to ring bundle</p>

#### DEV_NACK_RETRY_CNT field

<p>Number of retries before giving up</p>

#### DEVICE field

<p>Device type:
0 - I3C device,
1 - I2C device.</p>

#### AUTOCMD_MASK field

<p>IBI mask</p>

#### AUTOCMD_VALUE field

<p>IBI value that triggers auto command</p>

#### AUTOCMD_MODE field

<p>Auto command mode and speed</p>

#### AUTOCMD_HDR_CODE field

<p>Device auto command in HDR mode</p>

## DCT memory

- Absolute Address: 0x800
- Base Offset: 0x800
- Size: 0x800

|Offset|   Identifier  |Name|
|------|---------------|----|
|  0x0 |DCT_MEMORY[128]|  — |

### DCT_MEMORY register

- Absolute Address: 0x800
- Base Offset: 0x0
- Size: 0x800
- Array Dimensions: [128]
- Array Stride: 0x10
- Total Size: 0x800

| Bits |   Identifier  |Access|Reset|      Name     |
|------|---------------|------|-----|---------------|
| 31:0 |     PID_HI    |   r  |  —  |     PID_HI    |
| 47:32|     PID_LO    |   r  |  —  |     PID_LO    |
| 71:64|      DCR      |   r  |  —  |      DCR      |
| 79:72|      BCR      |   r  |  —  |      BCR      |
|103:96|DYNAMIC_ADDRESS|   r  |  —  |DYNAMIC_ADDRESS|

#### PID_HI field

<p>Device Provisional ID High</p>

#### PID_LO field

<p>Device Provisional ID Low</p>

#### DCR field

<p>Value of the I3C device's Device Characteristics Register</p>

#### BCR field

<p>Value of the I3C device's Bus Characteristics Register</p>

#### DYNAMIC_ADDRESS field

<p>Device I3C Dynamic Address after ENTDAA</p>
