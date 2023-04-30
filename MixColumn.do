vdel -all -lib work
vlib work
vcom -2008 Rijndael.vhd
vcom -2008 testbench_utils.vhd
vcom -2008 MixColumn_tb.vhd
vsim work.testbench(behavior)
view wave
add wave -r /*
radix hex
run 200 us
