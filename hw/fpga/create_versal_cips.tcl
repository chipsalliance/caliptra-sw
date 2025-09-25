# Licensed under the Apache-2.0 license

# Create interface ports
set ch0_lpddr4_c0 [ create_bd_intf_port -mode Master -vlnv xilinx.com:interface:lpddr4_rtl:1.0 ch0_lpddr4_c0 ]

set ch1_lpddr4_c0 [ create_bd_intf_port -mode Master -vlnv xilinx.com:interface:lpddr4_rtl:1.0 ch1_lpddr4_c0 ]

set lpddr4_sma_clk1 [ create_bd_intf_port -mode Slave -vlnv xilinx.com:interface:diff_clock_rtl:1.0 lpddr4_sma_clk1 ]
set_property -dict [ list \
  CONFIG.FREQ_HZ {200321000} \
  ] $lpddr4_sma_clk1

set ch0_lpddr4_c1 [ create_bd_intf_port -mode Master -vlnv xilinx.com:interface:lpddr4_rtl:1.0 ch0_lpddr4_c1 ]

set ch1_lpddr4_c1 [ create_bd_intf_port -mode Master -vlnv xilinx.com:interface:lpddr4_rtl:1.0 ch1_lpddr4_c1 ]

set lpddr4_sma_clk2 [ create_bd_intf_port -mode Slave -vlnv xilinx.com:interface:diff_clock_rtl:1.0 lpddr4_sma_clk2 ]
set_property -dict [ list \
  CONFIG.FREQ_HZ {200321000} \
  ] $lpddr4_sma_clk2

set ddr4_dimm1 [ create_bd_intf_port -mode Master -vlnv xilinx.com:interface:ddr4_rtl:1.0 ddr4_dimm1 ]

set ddr4_dimm1_sma_clk [ create_bd_intf_port -mode Slave -vlnv xilinx.com:interface:diff_clock_rtl:1.0 ddr4_dimm1_sma_clk ]
set_property -dict [ list \
  CONFIG.FREQ_HZ {200000000} \
  ] $ddr4_dimm1_sma_clk

create_bd_cell -type ip -vlnv xilinx.com:ip:versal_cips ps_0
set_property -dict [list \
  CONFIG.DDR_MEMORY_MODE {Custom} \
  CONFIG.DEBUG_MODE {JTAG} \
  CONFIG.DESIGN_MODE {1} \
  CONFIG.PS_PL_CONNECTIVITY_MODE {Custom} \
] [get_bd_cells ps_0]
set_property CONFIG.PS_PMC_CONFIG [list \
    CLOCK_MODE {Custom} \
    DDR_MEMORY_MODE {Connectivity to DDR via NOC} \
    DEBUG_MODE {JTAG} \
    DESIGN_MODE {1} \
    PMC_CRP_PL0_REF_CTRL_FREQMHZ "$CORE_CLK_MHZ" \
    PMC_CRP_PL1_REF_CTRL_FREQMHZ "$I3C_CLK_MHZ" \
    PMC_GPIO0_MIO_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 0 .. 25}}} \
    PMC_GPIO1_MIO_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 26 .. 51}}} \
    PMC_MIO37 {{AUX_IO 0} {DIRECTION out} {DRIVE_STRENGTH 8mA} {OUTPUT_DATA high} {PULL pullup} {SCHMITT 0} {SLEW slow} {USAGE GPIO}} \
    PMC_OSPI_PERIPHERAL {{ENABLE 0} {IO {PMC_MIO 0 .. 11}} {MODE Single}} \
    PMC_QSPI_COHERENCY {0} \
    PMC_QSPI_FBCLK {{ENABLE 1} {IO {PMC_MIO 6}}} \
    PMC_QSPI_PERIPHERAL_DATA_MODE {x4} \
    PMC_QSPI_PERIPHERAL_ENABLE {1} \
    PMC_QSPI_PERIPHERAL_MODE {Dual Parallel} \
    PMC_REF_CLK_FREQMHZ {33.3333} \
    PMC_SD1 {{CD_ENABLE 1} {CD_IO {PMC_MIO 28}} {POW_ENABLE 1} {POW_IO {PMC_MIO 51}} {RESET_ENABLE 0} {RESET_IO {PMC_MIO 12}} {WP_ENABLE 0} {WP_IO {PMC_MIO 1}}} \
    PMC_SD1_COHERENCY {0} \
    PMC_SD1_DATA_TRANSFER_MODE {8Bit} \
    PMC_SD1_PERIPHERAL {{CLK_100_SDR_OTAP_DLY 0x3} {CLK_200_SDR_OTAP_DLY 0x2} {CLK_50_DDR_ITAP_DLY 0x36} {CLK_50_DDR_OTAP_DLY 0x3} {CLK_50_SDR_ITAP_DLY 0x2C} {CLK_50_SDR_OTAP_DLY 0x4} {ENABLE 1} {IO {PMC_MIO 26 .. 36}}} \
    PMC_SD1_SLOT_TYPE {SD 3.0} \
    PMC_USE_PMC_NOC_AXI0 {1} \
    PS_CAN1_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 40 .. 41}}} \
    PS_CRL_CAN1_REF_CTRL_FREQMHZ {160} \
    PS_ENET0_MDIO {{ENABLE 1} {IO {PS_MIO 24 .. 25}}} \
    PS_ENET0_PERIPHERAL {{ENABLE 1} {IO {PS_MIO 0 .. 11}}} \
    PS_ENET1_PERIPHERAL {{ENABLE 1} {IO {PS_MIO 12 .. 23}}} \
    PS_GEN_IPI0_ENABLE {1} \
    PS_GEN_IPI0_MASTER {A72} \
    PS_GEN_IPI1_ENABLE {1} \
    PS_GEN_IPI2_ENABLE {1} \
    PS_GEN_IPI3_ENABLE {1} \
    PS_GEN_IPI4_ENABLE {1} \
    PS_GEN_IPI5_ENABLE {1} \
    PS_GEN_IPI6_ENABLE {1} \
    PS_GPIO_EMIO_PERIPHERAL_ENABLE {1} \
    PS_GPIO_EMIO_WIDTH {15} \
    PS_HSDP_EGRESS_TRAFFIC {JTAG} \
    PS_HSDP_INGRESS_TRAFFIC {JTAG} \
    PS_HSDP_MODE {NONE} \
    PS_I2C0_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 46 .. 47}}} \
    PS_I2C1_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 44 .. 45}}} \
    PS_MIO19 {{AUX_IO 0} {DIRECTION in} {DRIVE_STRENGTH 8mA} {OUTPUT_DATA default} {PULL disable} {SCHMITT 0} {SLEW slow} {USAGE Reserved}} \
    PS_MIO21 {{AUX_IO 0} {DIRECTION in} {DRIVE_STRENGTH 8mA} {OUTPUT_DATA default} {PULL disable} {SCHMITT 0} {SLEW slow} {USAGE Reserved}} \
    PS_MIO7 {{AUX_IO 0} {DIRECTION in} {DRIVE_STRENGTH 8mA} {OUTPUT_DATA default} {PULL disable} {SCHMITT 0} {SLEW slow} {USAGE Reserved}} \
    PS_MIO9 {{AUX_IO 0} {DIRECTION in} {DRIVE_STRENGTH 8mA} {OUTPUT_DATA default} {PULL disable} {SCHMITT 0} {SLEW slow} {USAGE Reserved}} \
    PS_NUM_FABRIC_RESETS {1} \
    PS_PCIE_EP_RESET1_IO {None} \
    PS_PCIE_EP_RESET2_IO {None} \
    PS_PCIE_RESET {{ENABLE 1}} \
    PS_PL_CONNECTIVITY_MODE {Custom} \
    PS_UART0_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 42 .. 43}}} \
    PS_USB3_PERIPHERAL {{ENABLE 1} {IO {PMC_MIO 13 .. 25}}} \
    PS_USE_FPD_CCI_NOC {1} \
    PS_USE_FPD_CCI_NOC0 {1} \
    PS_USE_M_AXI_FPD {1} \
    PS_USE_NOC_LPD_AXI0 {1} \
    PS_USE_PMCPL_CLK0 {1} \
    PS_USE_PMCPL_CLK1 {1} \
    PS_USE_PMCPL_CLK2 {0} \
    PS_USE_PMCPL_CLK3 {0} \
    SMON_ALARMS {Set_Alarms_On} \
    SMON_ENABLE_TEMP_AVERAGING {0} \
    SMON_TEMP_AVERAGING_SAMPLES {0} \
] [get_bd_cells ps_0]

# Create instance: axi_noc_0, and set properties
set axi_noc_0 [ create_bd_cell -type ip -vlnv xilinx.com:ip:axi_noc axi_noc_0 ]
set_property -dict [list \
  CONFIG.CH0_DDR4_0_BOARD_INTERFACE {ddr4_dimm1} \
  CONFIG.MC_CHAN_REGION1 {DDR_LOW1} \
  CONFIG.MC_SYSTEM_CLOCK {Differential} \
  CONFIG.NUM_CLKS {6} \
  CONFIG.NUM_MC {1} \
  CONFIG.NUM_MCP {4} \
  CONFIG.NUM_MI {0} \
  CONFIG.NUM_NMI {4} \
  CONFIG.NUM_SI {6} \
  CONFIG.sys_clk0_BOARD_INTERFACE {ddr4_dimm1_sma_clk} \
] $axi_noc_0


set_property -dict [ list \
  CONFIG.REGION {0} \
  CONFIG.CONNECTIONS {M00_INI {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}} MC_3 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
  CONFIG.DEST_IDS {} \
  CONFIG.NOC_PARAMS {} \
  CONFIG.CATEGORY {ps_cci} \
] [get_bd_intf_pins /axi_noc_0/S00_AXI]

set_property -dict [ list \
  CONFIG.REGION {0} \
  CONFIG.CONNECTIONS {M01_INI {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}} MC_2 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
  CONFIG.DEST_IDS {} \
  CONFIG.NOC_PARAMS {} \
  CONFIG.CATEGORY {ps_cci} \
] [get_bd_intf_pins /axi_noc_0/S01_AXI]

set_property -dict [ list \
  CONFIG.REGION {0} \
  CONFIG.CONNECTIONS {M02_INI {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}} MC_0 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
  CONFIG.DEST_IDS {} \
  CONFIG.NOC_PARAMS {} \
  CONFIG.CATEGORY {ps_cci} \
] [get_bd_intf_pins /axi_noc_0/S02_AXI]

set_property -dict [ list \
  CONFIG.REGION {0} \
  CONFIG.CONNECTIONS {M03_INI {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}} MC_1 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
  CONFIG.DEST_IDS {} \
  CONFIG.NOC_PARAMS {} \
  CONFIG.CATEGORY {ps_cci} \
] [get_bd_intf_pins /axi_noc_0/S03_AXI]

set_property -dict [ list \
  CONFIG.REGION {0} \
  CONFIG.CONNECTIONS {M00_INI {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}} MC_3 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
  CONFIG.DEST_IDS {} \
  CONFIG.NOC_PARAMS {} \
  CONFIG.CATEGORY {ps_rpu} \
] [get_bd_intf_pins /axi_noc_0/S04_AXI]

set_property -dict [ list \
  CONFIG.REGION {0} \
  CONFIG.CONNECTIONS {M01_INI {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}} MC_2 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
  CONFIG.DEST_IDS {} \
  CONFIG.NOC_PARAMS {} \
  CONFIG.CATEGORY {ps_pmc} \
] [get_bd_intf_pins /axi_noc_0/S05_AXI]

set_property -dict [ list \
  CONFIG.ASSOCIATED_BUSIF {S00_AXI} \
] [get_bd_pins /axi_noc_0/aclk0]

set_property -dict [ list \
  CONFIG.ASSOCIATED_BUSIF {S01_AXI} \
] [get_bd_pins /axi_noc_0/aclk1]

set_property -dict [ list \
  CONFIG.ASSOCIATED_BUSIF {S02_AXI} \
] [get_bd_pins /axi_noc_0/aclk2]

set_property -dict [ list \
  CONFIG.ASSOCIATED_BUSIF {S03_AXI} \
] [get_bd_pins /axi_noc_0/aclk3]

set_property -dict [ list \
  CONFIG.ASSOCIATED_BUSIF {S04_AXI} \
] [get_bd_pins /axi_noc_0/aclk4]

set_property -dict [ list \
  CONFIG.ASSOCIATED_BUSIF {S05_AXI} \
] [get_bd_pins /axi_noc_0/aclk5]

# Create instance: axi_noc_mc, and set properties
set axi_noc_mc [ create_bd_cell -type ip -vlnv xilinx.com:ip:axi_noc axi_noc_mc ]
set_property -dict [list \
  CONFIG.CH0_LPDDR4_0_BOARD_INTERFACE {ch0_lpddr4_c0} \
  CONFIG.CH0_LPDDR4_1_BOARD_INTERFACE {ch0_lpddr4_c1} \
  CONFIG.CH1_LPDDR4_0_BOARD_INTERFACE {ch1_lpddr4_c0} \
  CONFIG.CH1_LPDDR4_1_BOARD_INTERFACE {ch1_lpddr4_c1} \
  CONFIG.MC_CHAN_REGION0 {DDR_CH1} \
  CONFIG.MC_DM_WIDTH {4} \
  CONFIG.MC_DQS_WIDTH {4} \
  CONFIG.MC_DQ_WIDTH {32} \
  CONFIG.MC_SYSTEM_CLOCK {Differential} \
  CONFIG.NUM_MC {2} \
  CONFIG.NUM_MCP {4} \
  CONFIG.NUM_MI {0} \
  CONFIG.NUM_NSI {4} \
  CONFIG.NUM_SI {0} \
  CONFIG.sys_clk0_BOARD_INTERFACE {lpddr4_sma_clk1} \
  CONFIG.sys_clk1_BOARD_INTERFACE {lpddr4_sma_clk2} \
] $axi_noc_mc


set_property -dict [ list \
  CONFIG.CONNECTIONS {MC_3 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
] [get_bd_intf_pins /axi_noc_mc/S00_INI]

set_property -dict [ list \
  CONFIG.CONNECTIONS {MC_2 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
] [get_bd_intf_pins /axi_noc_mc/S01_INI]

set_property -dict [ list \
  CONFIG.CONNECTIONS {MC_0 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
] [get_bd_intf_pins /axi_noc_mc/S02_INI]

set_property -dict [ list \
  CONFIG.CONNECTIONS {MC_1 {read_bw {100} write_bw {100} read_avg_burst {4} write_avg_burst {4} initial_boot {true}}} \
] [get_bd_intf_pins /axi_noc_mc/S03_INI]

# Create variables to adapt between PS
set ps_m_axi ps_0/M_AXI_FPD
set ps_pl_clk ps_0/pl0_ref_clk
set ps_axi_aclk ps_0/m_axi_fpd_aclk
set ps_pl_resetn ps_0/pl0_resetn
set ps_gpio_i ps_0/LPD_GPIO_i
set ps_gpio_o ps_0/LPD_GPIO_o

# Connect DDR
connect_bd_intf_net -intf_net axi_noc_0_CH0_DDR4_0 [get_bd_intf_ports ddr4_dimm1] [get_bd_intf_pins axi_noc_0/CH0_DDR4_0]
connect_bd_intf_net -intf_net axi_noc_0_M00_INI [get_bd_intf_pins axi_noc_0/M00_INI] [get_bd_intf_pins axi_noc_mc/S00_INI]
connect_bd_intf_net -intf_net axi_noc_0_M01_INI [get_bd_intf_pins axi_noc_0/M01_INI] [get_bd_intf_pins axi_noc_mc/S01_INI]
connect_bd_intf_net -intf_net axi_noc_0_M02_INI [get_bd_intf_pins axi_noc_0/M02_INI] [get_bd_intf_pins axi_noc_mc/S02_INI]
connect_bd_intf_net -intf_net axi_noc_0_M03_INI [get_bd_intf_pins axi_noc_0/M03_INI] [get_bd_intf_pins axi_noc_mc/S03_INI]
connect_bd_intf_net -intf_net axi_noc_mc_CH0_LPDDR4_0 [get_bd_intf_ports ch0_lpddr4_c0] [get_bd_intf_pins axi_noc_mc/CH0_LPDDR4_0]
connect_bd_intf_net -intf_net axi_noc_mc_CH0_LPDDR4_1 [get_bd_intf_ports ch0_lpddr4_c1] [get_bd_intf_pins axi_noc_mc/CH0_LPDDR4_1]
connect_bd_intf_net -intf_net axi_noc_mc_CH1_LPDDR4_0 [get_bd_intf_ports ch1_lpddr4_c0] [get_bd_intf_pins axi_noc_mc/CH1_LPDDR4_0]
connect_bd_intf_net -intf_net axi_noc_mc_CH1_LPDDR4_1 [get_bd_intf_ports ch1_lpddr4_c1] [get_bd_intf_pins axi_noc_mc/CH1_LPDDR4_1]
connect_bd_intf_net -intf_net ddr4_dimm1_sma_clk_1 [get_bd_intf_ports ddr4_dimm1_sma_clk] [get_bd_intf_pins axi_noc_0/sys_clk0]
connect_bd_intf_net -intf_net lpddr4_sma_clk1_1 [get_bd_intf_ports lpddr4_sma_clk1] [get_bd_intf_pins axi_noc_mc/sys_clk0]
connect_bd_intf_net -intf_net lpddr4_sma_clk2_1 [get_bd_intf_ports lpddr4_sma_clk2] [get_bd_intf_pins axi_noc_mc/sys_clk1]
connect_bd_intf_net -intf_net ps_0_FPD_CCI_NOC_0 [get_bd_intf_pins ps_0/FPD_CCI_NOC_0] [get_bd_intf_pins axi_noc_0/S00_AXI]
connect_bd_intf_net -intf_net ps_0_FPD_CCI_NOC_1 [get_bd_intf_pins ps_0/FPD_CCI_NOC_1] [get_bd_intf_pins axi_noc_0/S01_AXI]
connect_bd_intf_net -intf_net ps_0_FPD_CCI_NOC_2 [get_bd_intf_pins ps_0/FPD_CCI_NOC_2] [get_bd_intf_pins axi_noc_0/S02_AXI]
connect_bd_intf_net -intf_net ps_0_FPD_CCI_NOC_3 [get_bd_intf_pins ps_0/FPD_CCI_NOC_3] [get_bd_intf_pins axi_noc_0/S03_AXI]
connect_bd_intf_net -intf_net ps_0_LPD_AXI_NOC_0 [get_bd_intf_pins ps_0/LPD_AXI_NOC_0] [get_bd_intf_pins axi_noc_0/S04_AXI]
connect_bd_intf_net -intf_net ps_0_PMC_NOC_AXI_0 [get_bd_intf_pins ps_0/PMC_NOC_AXI_0] [get_bd_intf_pins axi_noc_0/S05_AXI]

# Create port connections
connect_bd_net -net ps_0_fpd_cci_noc_axi0_clk  [get_bd_pins ps_0/fpd_cci_noc_axi0_clk] \
[get_bd_pins axi_noc_0/aclk0]
connect_bd_net -net ps_0_fpd_cci_noc_axi1_clk  [get_bd_pins ps_0/fpd_cci_noc_axi1_clk] \
[get_bd_pins axi_noc_0/aclk1]
connect_bd_net -net ps_0_fpd_cci_noc_axi2_clk  [get_bd_pins ps_0/fpd_cci_noc_axi2_clk] \
[get_bd_pins axi_noc_0/aclk2]
connect_bd_net -net ps_0_fpd_cci_noc_axi3_clk  [get_bd_pins ps_0/fpd_cci_noc_axi3_clk] \
[get_bd_pins axi_noc_0/aclk3]
connect_bd_net -net ps_0_lpd_axi_noc_clk  [get_bd_pins ps_0/lpd_axi_noc_clk] \
[get_bd_pins axi_noc_0/aclk4]
connect_bd_net -net ps_0_pmc_axi_noc_axi0_clk  [get_bd_pins ps_0/pmc_axi_noc_axi0_clk] \
[get_bd_pins axi_noc_0/aclk5]

# Create DRAM address segments
assign_bd_address -offset 0x00000000 -range 0x80000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_0] [get_bd_addr_segs axi_noc_0/S00_AXI/C3_DDR_LOW0] -force
assign_bd_address -offset 0x000800000000 -range 0x000180000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_0] [get_bd_addr_segs axi_noc_0/S00_AXI/C3_DDR_LOW1] -force
assign_bd_address -offset 0x050000000000 -range 0x000200000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_0] [get_bd_addr_segs axi_noc_mc/S00_INI/C3_DDR_CH1x2] -force
assign_bd_address -offset 0x00000000 -range 0x80000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_1] [get_bd_addr_segs axi_noc_0/S01_AXI/C2_DDR_LOW0] -force
assign_bd_address -offset 0x000800000000 -range 0x000180000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_1] [get_bd_addr_segs axi_noc_0/S01_AXI/C2_DDR_LOW1] -force
assign_bd_address -offset 0x050000000000 -range 0x000200000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_1] [get_bd_addr_segs axi_noc_mc/S01_INI/C2_DDR_CH1x2] -force
assign_bd_address -offset 0x00000000 -range 0x80000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_2] [get_bd_addr_segs axi_noc_0/S02_AXI/C0_DDR_LOW0] -force
assign_bd_address -offset 0x000800000000 -range 0x000180000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_2] [get_bd_addr_segs axi_noc_0/S02_AXI/C0_DDR_LOW1] -force
assign_bd_address -offset 0x050000000000 -range 0x000200000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_2] [get_bd_addr_segs axi_noc_mc/S02_INI/C0_DDR_CH1x2] -force
assign_bd_address -offset 0x00000000 -range 0x80000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_3] [get_bd_addr_segs axi_noc_0/S03_AXI/C1_DDR_LOW0] -force
assign_bd_address -offset 0x000800000000 -range 0x000180000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_3] [get_bd_addr_segs axi_noc_0/S03_AXI/C1_DDR_LOW1] -force
assign_bd_address -offset 0x050000000000 -range 0x000200000000 -target_address_space [get_bd_addr_spaces ps_0/FPD_CCI_NOC_3] [get_bd_addr_segs axi_noc_mc/S03_INI/C1_DDR_CH1x2] -force
assign_bd_address -offset 0x00000000 -range 0x80000000 -target_address_space [get_bd_addr_spaces ps_0/LPD_AXI_NOC_0] [get_bd_addr_segs axi_noc_0/S04_AXI/C3_DDR_LOW0] -force
assign_bd_address -offset 0x000800000000 -range 0x000180000000 -target_address_space [get_bd_addr_spaces ps_0/LPD_AXI_NOC_0] [get_bd_addr_segs axi_noc_0/S04_AXI/C3_DDR_LOW1] -force
assign_bd_address -offset 0x050000000000 -range 0x000200000000 -target_address_space [get_bd_addr_spaces ps_0/LPD_AXI_NOC_0] [get_bd_addr_segs axi_noc_mc/S00_INI/C3_DDR_CH1x2] -force
assign_bd_address -offset 0x00000000 -range 0x80000000 -target_address_space [get_bd_addr_spaces ps_0/PMC_NOC_AXI_0] [get_bd_addr_segs axi_noc_0/S05_AXI/C2_DDR_LOW0] -force
assign_bd_address -offset 0x000800000000 -range 0x000180000000 -target_address_space [get_bd_addr_spaces ps_0/PMC_NOC_AXI_0] [get_bd_addr_segs axi_noc_0/S05_AXI/C2_DDR_LOW1] -force
assign_bd_address -offset 0x050000000000 -range 0x000200000000 -target_address_space [get_bd_addr_spaces ps_0/PMC_NOC_AXI_0] [get_bd_addr_segs axi_noc_mc/S01_INI/C2_DDR_CH1x2] -force
