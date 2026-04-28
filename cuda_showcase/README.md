# CUDA Showcase

This directory contains a native CUDA C/C++ benchmark that demonstrates GPU acceleration on a measurable workload derived from `agent-hardener` reports.

## What It Measures

The benchmark loads compact CSV data exported from `report.json` files and computes:

- total record count
- success count
- iteration sum
- total score sum
- maximum score
- per-category counts
- per-category score sums

The CPU and GPU implementations use the same input format and compare outputs directly.

## Build

From this directory:

```bash
make cpu
make gpu
```

If your system uses a different CUDA install path, edit `CUDA_HOME` in the `Makefile` or set it from the command line.

## Export Input

Generate benchmark input from one report or a directory of reports:

```bash
python tools/export_metrics_input.py ..\hardener_output --output data\benchmark_input.csv --success-threshold 0.95
```

## Run

CPU only:

```bash
bin\benchmark_cpu --input data\benchmark_input.csv --threshold 0.95
```

GPU only:

```bash
bin\benchmark_cuda --mode gpu --input data\benchmark_input.csv --threshold 0.95 --block-size 256
```

Compare mode:

```bash
bin\benchmark_cuda --mode compare --input data\benchmark_input.csv --threshold 0.95 --tolerance 1e-5 --block-size 256
```

## Demo Notes

- Use `--mode cpu` on a laptop without CUDA hardware.
- Use `--mode compare` on the GPU server to show parity and speedup.
- Increase the input size by exporting multiple `report.json` files if the benchmark is too small to show a clear GPU advantage.
