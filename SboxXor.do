vdel -all -lib work
vlib work
vcom -2008 Rijndael.vhd
vcom -2008 testbench_utils.vhd
vcom -2008 SboxXor_tb.vhd
vsim work.testbench(behavior)
run 1 us
