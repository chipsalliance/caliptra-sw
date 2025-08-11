
set adbDir $fpgaDir/../$RTL_VERSION/rtl/submodules/adams-bridge

if { [file exists $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv] == 0 } {
    puts "ERROR: $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv not found"
    puts "Adam's bridge submodule may not be initialized"
    puts "Try: git submodule update --init --recursive"
    exit
}

add_files $adbDir/src/abr_prim/rtl/abr_prim_flop_macros.sv

# Initial list from mldsa_top_tb.vf
add_files $adbDir/src/abr_top/rtl/abr_config_defines.svh
add_files $adbDir/src/abr_top/rtl/abr_params_pkg.sv
add_files $adbDir/src/abr_top/rtl/abr_reg_pkg.sv

add_files $adbDir/src/abr_libs/rtl/abr_sva.svh
add_files $adbDir/src/abr_libs/rtl/abr_macros.svh

add_files [ glob $adbDir/src/abr_libs/rtl/*.sv ]

add_files $adbDir/src/abr_sampler_top/rtl/abr_sampler_pkg.sv
add_files $adbDir/src/sample_in_ball/rtl/sample_in_ball_pkg.sv
add_files $adbDir/src/sample_in_ball/rtl/sib_mem.sv

add_files [ glob $adbDir/src/abr_prim/rtl/*.sv ]
add_files [ glob $adbDir/src/abr_prim/rtl/*.svh ]

add_files [ glob $adbDir/src/ntt_top/rtl/*.sv ]
add_files $adbDir/src/ntt_top/tb/ntt_ram_tdp_file.sv
add_files $adbDir/src/ntt_top/tb/ntt_wrapper.sv
add_files $adbDir/src/norm_check/rtl/norm_check_defines_pkg.sv
add_files $adbDir/src/abr_top/tb/abr_top_tb.sv
add_files $adbDir/src/rej_bounded/rtl/rej_bounded_ctrl.sv
add_files $adbDir/src/rej_bounded/rtl/rej_bounded2.sv
add_files $adbDir/src/rej_sampler/rtl/rej_sampler_ctrl.sv
add_files $adbDir/src/rej_sampler/rtl/rej_sampler.sv
add_files $adbDir/src/exp_mask/rtl/exp_mask_ctrl.sv
add_files $adbDir/src/exp_mask/rtl/exp_mask.sv
add_files $adbDir/src/sample_in_ball/rtl/sample_in_ball_ctrl.sv
add_files $adbDir/src/sample_in_ball/rtl/sample_in_ball_shuffler.sv
add_files $adbDir/src/sample_in_ball/rtl/sample_in_ball.sv
add_files $adbDir/src/abr_sha3/rtl/abr_sha3_pkg.sv
add_files $adbDir/src/abr_prim_generic/rtl/abr_prim_generic_flop_en.sv
add_files $adbDir/src/abr_prim_generic/rtl/abr_prim_generic_flop.sv
add_files $adbDir/src/abr_prim_generic/rtl/abr_prim_generic_buf.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_flop_en.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_cdc_rand_delay.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_flop_2sync.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_lfsr.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_mubi4_sync.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_diff_decode.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_sec_anchor_buf.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_slicer.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_count.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_sparse_fsm_flop.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_dom_and_2share.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_sec_anchor_flop.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_reg_we_check.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_packer_fifo.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_max_tree.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_subreg_arb.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_subreg.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_intr_hw.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_onehot_check.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_mubi8_sync.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_fifo_sync_cnt.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_buf.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_alert_receiver.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_flop.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_alert_sender.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_fifo_sync.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_arbiter_ppc.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_sum_tree.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_subreg_ext.sv
add_files $adbDir/src/abr_prim/rtl/abr_prim_edge_detector.sv
add_files $adbDir/src/abr_sha3/rtl/abr_keccak_round.sv
add_files $adbDir/src/abr_sha3/rtl/abr_keccak_2share.sv
add_files $adbDir/src/abr_sha3/rtl/abr_sha3pad.sv
add_files $adbDir/src/abr_sha3/rtl/abr_sha3.sv
add_files $adbDir/src/abr_sampler_top/rtl/abr_sampler_top.sv
add_files $adbDir/src/decompose/rtl/decompose_defines_pkg.sv
add_files $adbDir/src/decompose/rtl/decompose.sv
add_files $adbDir/src/decompose/rtl/decompose_r1_lut.sv
add_files $adbDir/src/decompose/rtl/decompose_w1_mem.sv
add_files $adbDir/src/decompose/rtl/decompose_mod_2gamma2.sv
add_files $adbDir/src/decompose/rtl/decompose_ctrl.sv
add_files $adbDir/src/decompose/rtl/decompose_w1_encode.sv
add_files $adbDir/src/decompose/rtl/decompose_usehint.sv
add_files $adbDir/src/sk_decode/rtl/skdecode_defines_pkg.sv
add_files $adbDir/src/sk_encode/rtl/skencode.sv
add_files $adbDir/src/sk_decode/rtl/skdecode_top.sv
add_files $adbDir/src/sk_decode/rtl/skdecode_ctrl.sv
add_files $adbDir/src/sk_decode/rtl/skdecode_s1s2_unpack.sv
add_files $adbDir/src/sk_decode/rtl/skdecode_t0_unpack.sv
add_files $adbDir/src/makehint/rtl/makehint_defines_pkg.sv
add_files $adbDir/src/makehint/rtl/hintgen.sv
add_files $adbDir/src/makehint/rtl/makehint.sv
add_files $adbDir/src/norm_check/rtl/norm_check.sv
add_files $adbDir/src/norm_check/rtl/norm_check_ctrl.sv
add_files $adbDir/src/norm_check/rtl/norm_check_top.sv
add_files $adbDir/src/sig_encode_z/rtl/sigencode_z_defines_pkg.sv
add_files $adbDir/src/sig_encode_z/rtl/sigencode_z_top.sv
add_files $adbDir/src/sig_encode_z/rtl/sigencode_z_unit.sv
add_files $adbDir/src/sigdecode_h/rtl/sigdecode_h_defines_pkg.sv
add_files $adbDir/src/sigdecode_h/rtl/sigdecode_h.sv
add_files $adbDir/src/sigdecode_h/rtl/sigdecode_h_ctrl.sv
add_files $adbDir/src/sig_decode_z/rtl/sigdecode_z_defines_pkg.sv
add_files $adbDir/src/sig_decode_z/rtl/sigdecode_z_top.sv
add_files $adbDir/src/sig_decode_z/rtl/sigdecode_z_unit.sv
add_files $adbDir/src/pk_decode/rtl/pkdecode.sv
add_files $adbDir/src/power2round/rtl/power2round_defines_pkg.sv
add_files $adbDir/src/power2round/rtl/power2round_top.sv
add_files $adbDir/src/power2round/rtl/power2round_ctrl.sv
add_files $adbDir/src/power2round/rtl/power2round_core.sv
add_files $adbDir/src/power2round/rtl/power2round_skencode.sv

add_files [ glob $adbDir/src/abr_top/rtl/*.sv ]
