#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#define CUDA_CHECK(call) do { \
  cudaError_t err = (call); \
  if (err != cudaSuccess) { \
    std::cerr << "CUDA error: " << cudaGetErrorString(err) << "\n"; \
    std::exit(1); \
  } \
} while (0)

struct Row {
  float score;
  int iterations;
  int success;
};

__device__ float atomicMaxFloat(float* address, float val) {
  int* address_as_i = reinterpret_cast<int*>(address);
  int old = *address_as_i, assumed;
  while (__int_as_float(old) < val) {
    assumed = old;
    old = atomicCAS(address_as_i, assumed, __float_as_int(val));
    if (assumed == old) break;
  }
  return __int_as_float(old);
}

__device__ float harden_score(float score, int iterations, int success) {
  float value = score;
  const float drift = 1.0005f + 0.0001f * static_cast<float>(iterations);
  const float bias = success ? 0.00025f : -0.00015f;
  for (int pass = 0; pass < 256; ++pass) {
    value = value * drift + bias;
    value -= floorf(value);
  }
  return value;
}

__global__ void metrics_kernel(const float* scores, const int* iterations, const int* successes, int n,
                               int* total_rows, int* success_count,
                               float* score_sum, float* max_score) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;

  const float hardened = harden_score(scores[i], iterations[i], successes[i]);
  atomicAdd(total_rows, 1);
  atomicAdd(success_count, successes[i]);
  atomicAdd(score_sum, hardened);
  atomicMaxFloat(max_score, hardened);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: ./gpu_metrics <csv_file>\n";
    return 1;
  }

  const auto load_start = std::chrono::steady_clock::now();
  std::ifstream file(argv[1]);
  if (!file.is_open()) {
    std::cerr << "Could not open file: " << argv[1] << "\n";
    return 1;
  }

  std::string line;
  std::getline(file, line); // skip header

  std::vector<float> h_scores;
  std::vector<int> h_iterations;
  std::vector<int> h_successes;

  while (std::getline(file, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    std::string token;

    std::getline(ss, token, ','); // harm_category_index
    std::getline(ss, token, ','); // final_score
    float score = std::stof(token);
    std::getline(ss, token, ','); // iterations
    int iterations = std::stoi(token);
    std::getline(ss, token, ','); // success_flag
    int success = std::stoi(token);

    h_scores.push_back(score);
    h_iterations.push_back(iterations);
    h_successes.push_back(success);
  }
  const auto load_end = std::chrono::steady_clock::now();

  int n = static_cast<int>(h_scores.size());
  if (n == 0) {
    std::cerr << "No data rows found\n";
    return 1;
  }

  float* d_scores = nullptr;
  int* d_iterations = nullptr;
  int* d_successes = nullptr;
  int* d_total_rows = nullptr;
  int* d_success_count = nullptr;
  float* d_score_sum = nullptr;
  float* d_max_score = nullptr;

  CUDA_CHECK(cudaMalloc(&d_scores, n * sizeof(float)));
  CUDA_CHECK(cudaMalloc(&d_iterations, n * sizeof(int)));
  CUDA_CHECK(cudaMalloc(&d_successes, n * sizeof(int)));
  CUDA_CHECK(cudaMalloc(&d_total_rows, sizeof(int)));
  CUDA_CHECK(cudaMalloc(&d_success_count, sizeof(int)));
  CUDA_CHECK(cudaMalloc(&d_score_sum, sizeof(float)));
  CUDA_CHECK(cudaMalloc(&d_max_score, sizeof(float)));

  CUDA_CHECK(cudaMemcpy(d_scores, h_scores.data(), n * sizeof(float), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(d_iterations, h_iterations.data(), n * sizeof(int), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(d_successes, h_successes.data(), n * sizeof(int), cudaMemcpyHostToDevice));

  CUDA_CHECK(cudaMemset(d_total_rows, 0, sizeof(int)));
  CUDA_CHECK(cudaMemset(d_success_count, 0, sizeof(int)));
  CUDA_CHECK(cudaMemset(d_score_sum, 0, sizeof(float)));
  CUDA_CHECK(cudaMemset(d_max_score, 0, sizeof(float)));

  cudaEvent_t kernel_start = nullptr;
  cudaEvent_t kernel_stop = nullptr;
  CUDA_CHECK(cudaEventCreate(&kernel_start));
  CUDA_CHECK(cudaEventCreate(&kernel_stop));

  const int block_size = 256;
  const int grid_size = (n + block_size - 1) / block_size;
  CUDA_CHECK(cudaEventRecord(kernel_start));
  metrics_kernel<<<grid_size, block_size>>>(d_scores, d_iterations, d_successes, n, d_total_rows, d_success_count, d_score_sum, d_max_score);
  CUDA_CHECK(cudaGetLastError());
  CUDA_CHECK(cudaEventRecord(kernel_stop));
  CUDA_CHECK(cudaEventSynchronize(kernel_stop));

  float kernel_ms = 0.0f;
  CUDA_CHECK(cudaEventElapsedTime(&kernel_ms, kernel_start, kernel_stop));

  int total_rows = 0;
  int success_count = 0;
  float score_sum = 0.0f;
  float max_score = 0.0f;

  CUDA_CHECK(cudaMemcpy(&total_rows, d_total_rows, sizeof(int), cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(&success_count, d_success_count, sizeof(int), cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(&score_sum, d_score_sum, sizeof(float), cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(&max_score, d_max_score, sizeof(float), cudaMemcpyDeviceToHost));

  CUDA_CHECK(cudaEventDestroy(kernel_start));
  CUDA_CHECK(cudaEventDestroy(kernel_stop));
  CUDA_CHECK(cudaFree(d_scores));
  CUDA_CHECK(cudaFree(d_iterations));
  CUDA_CHECK(cudaFree(d_successes));
  CUDA_CHECK(cudaFree(d_total_rows));
  CUDA_CHECK(cudaFree(d_success_count));
  CUDA_CHECK(cudaFree(d_score_sum));
  CUDA_CHECK(cudaFree(d_max_score));

  const auto total_end = std::chrono::steady_clock::now();
  const double load_seconds = std::chrono::duration<double>(load_end - load_start).count();
  const double compute_seconds = static_cast<double>(kernel_ms) / 1000.0;
  const double total_seconds = std::chrono::duration<double>(total_end - load_start).count();

  std::cout << std::fixed << std::setprecision(6);
  std::cout << "load_seconds=" << load_seconds << "\n";
  std::cout << "compute_seconds=" << compute_seconds << "\n";
  std::cout << "total_seconds=" << total_seconds << "\n";
  std::cout << "total_rows=" << total_rows << "\n";
  std::cout << "success_count=" << success_count << "\n";
  std::cout << "score_sum=" << score_sum << "\n";
  std::cout << "max_score=" << max_score << "\n";
  return 0;
}
