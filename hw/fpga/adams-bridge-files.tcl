
set adbDir $fpgaDir/../$RTL_VERSION/rtl/submodules/adams-bridge

if { [file exists $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv] == 0 } {
    puts "ERROR: $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv not found"
    puts "Adam's bridge submodule may not be initialized"
    puts "Try: git submodule update --init --recursive"
    exit
}

add_files [ glob $adbDir/src/*/rtl/*.svh ]
add_files [ glob $adbDir/src/*/rtl/*.sv ]
