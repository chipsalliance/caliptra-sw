# Assign JTAG signals to pins on PMOD0
set_property PACKAGE_PIN G7 [get_ports jtag_tck_0]
set_property PACKAGE_PIN G6 [get_ports jtag_tdi_0]
set_property PACKAGE_PIN G8 [get_ports jtag_tdo_0]
set_property PACKAGE_PIN H6 [get_ports jtag_tms_0]
set_property PACKAGE_PIN H8 [get_ports jtag_trst_n_0]

# JTAG pin properties
set_property IOSTANDARD LVCMOS33 [get_ports jtag_tck_0]
set_property IOSTANDARD LVCMOS33 [get_ports jtag_tdi_0]
set_property IOSTANDARD LVCMOS33 [get_ports jtag_tdo_0]
set_property IOSTANDARD LVCMOS33 [get_ports jtag_tms_0]
set_property IOSTANDARD LVCMOS33 [get_ports jtag_trst_n_0]

# JTAG tck constraints
create_clock -period 10000.000 -name jtag_tck_0 -waveform {0.000 5000.000} [get_ports jtag_tck_0]
set_property CLOCK_DEDICATED_ROUTE FALSE [get_nets jtag_tck_0_IBUF_inst/O]
set_clock_groups -asynchronous -group [get_clocks -of_objects [get_pins]]
set_input_jitter jtag_tck_0 1.000

# Input pins delay
set_input_delay -clock jtag_tck_0 -clock_fall -min -5.000 [get_ports jtag_tdi_0]
set_input_delay -clock jtag_tck_0 -clock_fall -min -5.000 [get_ports jtag_tms_0]
set_input_delay -clock jtag_tck_0 -clock_fall -min -5.000 [get_ports jtag_trst_n_0]

set_input_delay -clock jtag_tck_0 -clock_fall -max 5.000 [get_ports jtag_tdi_0]
set_input_delay -clock jtag_tck_0 -clock_fall -max 5.000 [get_ports jtag_tms_0]
set_input_delay -clock jtag_tck_0 -clock_fall -max 5.000 [get_ports jtag_trst_n_0]

# Output pins delay
set_output_delay -clock [get_clocks jtag_tck_0] -min -5.000 [get_ports jtag_tdo_0]
set_output_delay -clock [get_clocks jtag_tck_0] -max 15.000 [get_ports jtag_tdo_0]

