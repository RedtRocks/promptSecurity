CUDA_HOME ?= C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.5
NVCC ?= nvcc
CXX ?= g++
SRC_DIR := src
INCLUDE_DIR := include
BIN_DIR := bin
BUILD_DIR := build
CXXFLAGS := -O3 -std=c++17 -I$(INCLUDE_DIR)
NVCCFLAGS := -O3 -std=c++17 -I$(INCLUDE_DIR)

CPU_BIN := $(BIN_DIR)/benchmark_cpu
CUDA_BIN := $(BIN_DIR)/benchmark_cuda

ifneq ($(strip $(CUDA_HOME)),)
NVCC := $(CUDA_HOME)/bin/nvcc
endif

.PHONY: all cpu gpu compare clean dirs

all: cpu gpu

cpu: dirs $(CPU_BIN)

gpu: dirs $(CUDA_BIN)

compare: gpu

dirs:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BUILD_DIR)

$(CPU_BIN): $(SRC_DIR)/benchmark_cpu.cpp $(INCLUDE_DIR)/common.hpp | dirs
	$(CXX) $(CXXFLAGS) $< -o $@

$(CUDA_BIN): $(SRC_DIR)/benchmark_cuda.cu $(INCLUDE_DIR)/common.hpp | dirs
	$(NVCC) $(NVCCFLAGS) $< -o $@

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
