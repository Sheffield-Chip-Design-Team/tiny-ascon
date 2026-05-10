# Cocotb Makefile for rtl/ascon_top

MAKEFLAGS=-j8

SIM ?= verilator
TOPLEVEL_LANG ?= verilog

EXTRA_ARGS += --threads 8
EXTRA_ARGS += --relative-includes
EXTRA_ARGS += -Wno-UNOPTFLAT

TOPLEVEL = ascon_top
MODULE = test

VERILOG_SOURCES = \
	$(PWD)/../rtl/ascon_top.v \
	$(PWD)/../rtl/ascon_core.v \
	$(PWD)/../rtl/ascon_permutation.v

include $(shell cocotb-config --makefiles)/Makefile.sim
