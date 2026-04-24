#include "common.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <string>

#include <cuda_runtime.h>

using namespace cuda_showcase;

#define CUDA_CHECK(call)                                                                      \
    do {                                                                                      \
        cudaError_t err__ = (call);                                                           \
        if (err__ != cudaSuccess) {                                                           \
            throw std::runtime_error(std::string("CUDA error: ") + cudaGetErrorString(err__)); \
        }                                                                                     \
    } while (0)

struct DeviceMetrics {
    std::int64_t total_records = 0;
    std::int64_t success_count = 0;
    std::int64_t iteration_sum = 0;
    float score_sum = 0.0f;
    float max_score = 0.0f;
    std::array<std::int64_t, kCategoryCount> category_counts{};
    std::array<float, kCategoryCount> category_score_sums{};
};

struct DeviceInput {
    int* category = nullptr;
    float* score = nullptr;
    int* iterations = nullptr;
    int* success = nullptr;
    std::size_t count = 0;
};

__device__ float atomicMaxFloat(float* address, float value) {
    int* int_address = reinterpret_cast<int*>(address);
    int old = *int_address;
    int assumed;
    while (__int_as_float(old) < value) {
        assumed = old;
        old = atomicCAS(int_address, assumed, __float_as_int(value));
        if (assumed == old) {
            break;
        }
    }
    return __int_as_float(old);
}

__global__ void accumulate_kernel(
    const int* category,
    const float* score,
    const int* iterations,
    const int* success,
    std::size_t count,
    float threshold,
    std::int64_t* total_records,
    std::int64_t* success_count,
    std::int64_t* iteration_sum,
    float* score_sum,
    float* max_score,
    std::int64_t* category_counts,
    float* category_score_sums) {
    const std::size_t index = static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index >= count) {
        return;
    }

    const int cat = category[index];
    const float s = score[index];
    const int iter = iterations[index];
    const int succ = success[index];

    atomicAdd(total_records, static_cast<std::int64_t>(1));
    atomicAdd(success_count, static_cast<std::int64_t>(succ || s >= threshold));
    atomicAdd(iteration_sum, static_cast<std::int64_t>(iter));
    atomicAdd(score_sum, s);
    atomicMaxFloat(max_score, s);
    atomicAdd(&category_counts[cat], static_cast<std::int64_t>(1));
    atomicAdd(&category_score_sums[cat], s);
}

static void print_usage() {
    std::cout << "Usage: benchmark_cuda --input <file> --mode <cpu|gpu|compare> [--threshold <float>] [--block-size <int>] [--tolerance <float>]\n";
}

static DeviceInput upload_input(const std::vector<Record>& records) {
    DeviceInput device_input;
    device_input.count = records.size();

    std::vector<int> categories(records.size());
    std::vector<float> scores(records.size());
    std::vector<int> iterations(records.size());
    std::vector<int> success(records.size());

    for (std::size_t i = 0; i < records.size(); ++i) {
        categories[i] = records[i].category;
        scores[i] = records[i].score;
        iterations[i] = records[i].iterations;
        success[i] = records[i].success;
    }

    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_input.category), categories.size() * sizeof(int)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_input.score), scores.size() * sizeof(float)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_input.iterations), iterations.size() * sizeof(int)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_input.success), success.size() * sizeof(int)));

    CUDA_CHECK(cudaMemcpy(device_input.category, categories.data(), categories.size() * sizeof(int), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_input.score, scores.data(), scores.size() * sizeof(float), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_input.iterations, iterations.data(), iterations.size() * sizeof(int), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_input.success, success.data(), success.size() * sizeof(int), cudaMemcpyHostToDevice));

    return device_input;
}

static void free_input(DeviceInput& input) {
    if (input.category) cudaFree(input.category);
    if (input.score) cudaFree(input.score);
    if (input.iterations) cudaFree(input.iterations);
    if (input.success) cudaFree(input.success);
    input = {};
}

static DeviceMetrics run_gpu_kernel(const std::vector<Record>& records, float threshold, int block_size) {
    DeviceInput input = upload_input(records);

    std::int64_t* d_total_records = nullptr;
    std::int64_t* d_success_count = nullptr;
    std::int64_t* d_iteration_sum = nullptr;
    float* d_score_sum = nullptr;
    float* d_max_score = nullptr;
    std::int64_t* d_category_counts = nullptr;
    float* d_category_score_sums = nullptr;

    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_total_records), sizeof(std::int64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_success_count), sizeof(std::int64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_iteration_sum), sizeof(std::int64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_score_sum), sizeof(float)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_max_score), sizeof(float)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_category_counts), kCategoryCount * sizeof(std::int64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_category_score_sums), kCategoryCount * sizeof(float)));

    CUDA_CHECK(cudaMemset(d_total_records, 0, sizeof(std::int64_t)));
    CUDA_CHECK(cudaMemset(d_success_count, 0, sizeof(std::int64_t)));
    CUDA_CHECK(cudaMemset(d_iteration_sum, 0, sizeof(std::int64_t)));
    CUDA_CHECK(cudaMemset(d_score_sum, 0, sizeof(float)));
    CUDA_CHECK(cudaMemset(d_max_score, 0, sizeof(float)));
    CUDA_CHECK(cudaMemset(d_category_counts, 0, kCategoryCount * sizeof(std::int64_t)));
    CUDA_CHECK(cudaMemset(d_category_score_sums, 0, kCategoryCount * sizeof(float)));

    const int grid_size = static_cast<int>((records.size() + block_size - 1) / block_size);
    accumulate_kernel<<<grid_size, block_size>>>(
        input.category,
        input.score,
        input.iterations,
        input.success,
        input.count,
        threshold,
        d_total_records,
        d_success_count,
        d_iteration_sum,
        d_score_sum,
        d_max_score,
        d_category_counts,
        d_category_score_sums);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    DeviceMetrics metrics;
    CUDA_CHECK(cudaMemcpy(&metrics.total_records, d_total_records, sizeof(std::int64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&metrics.success_count, d_success_count, sizeof(std::int64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&metrics.iteration_sum, d_iteration_sum, sizeof(std::int64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&metrics.score_sum, d_score_sum, sizeof(float), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&metrics.max_score, d_max_score, sizeof(float), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(metrics.category_counts.data(), d_category_counts, kCategoryCount * sizeof(std::int64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(metrics.category_score_sums.data(), d_category_score_sums, kCategoryCount * sizeof(float), cudaMemcpyDeviceToHost));

    free_input(input);
    cudaFree(d_total_records);
    cudaFree(d_success_count);
    cudaFree(d_iteration_sum);
    cudaFree(d_score_sum);
    cudaFree(d_max_score);
    cudaFree(d_category_counts);
    cudaFree(d_category_score_sums);

    return metrics;
}

static Metrics to_metrics(const DeviceMetrics& device_metrics) {
    Metrics metrics;
    metrics.total_records = device_metrics.total_records;
    metrics.success_count = device_metrics.success_count;
    metrics.iteration_sum = device_metrics.iteration_sum;
    metrics.score_sum = device_metrics.score_sum;
    metrics.max_score = device_metrics.max_score;
    metrics.category_counts = device_metrics.category_counts;
    metrics.category_score_sums = device_metrics.category_score_sums;
    return metrics;
}

static Metrics run_cpu_with_timing(const std::vector<Record>& records, float threshold, double& compute_seconds) {
    const auto compute_start = std::chrono::steady_clock::now();
    const Metrics metrics = compute_metrics_cpu(records, threshold);
    const auto compute_end = std::chrono::steady_clock::now();
    compute_seconds = std::chrono::duration<double>(compute_end - compute_start).count();
    return metrics;
}

static bool gpu_available() {
    int count = 0;
    const cudaError_t err = cudaGetDeviceCount(&count);
    return err == cudaSuccess && count > 0;
}

int main(int argc, char** argv) {
    std::string input_path;
    std::string mode = "compare";
    float threshold = 0.95f;
    float tolerance = 1e-5f;
    int block_size = 256;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--input" && i + 1 < argc) {
            input_path = argv[++i];
        } else if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--threshold" && i + 1 < argc) {
            threshold = std::stof(argv[++i]);
        } else if (arg == "--tolerance" && i + 1 < argc) {
            tolerance = std::stof(argv[++i]);
        } else if (arg == "--block-size" && i + 1 < argc) {
            block_size = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            print_usage();
            return 1;
        }
    }

    if (input_path.empty()) {
        std::cerr << "Missing required --input argument\n";
        print_usage();
        return 1;
    }

    if (block_size <= 0) {
        std::cerr << "--block-size must be positive\n";
        return 1;
    }

    try {
        const auto total_start = std::chrono::steady_clock::now();
        const auto load_start = std::chrono::steady_clock::now();
        const auto records = load_records_from_csv(input_path);
        const auto load_end = std::chrono::steady_clock::now();
        const double load_seconds = std::chrono::duration<double>(load_end - load_start).count();

        std::cout << "mode=" << mode << '\n';
        std::cout << "input=" << input_path << '\n';
        std::cout << "threshold=" << threshold << '\n';
        std::cout << "block_size=" << block_size << '\n';
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "load_seconds=" << load_seconds << '\n';

        if (mode == "cpu") {
            double compute_seconds = 0.0;
            const Metrics metrics = run_cpu_with_timing(records, threshold, compute_seconds);
            const auto total_end = std::chrono::steady_clock::now();
            const double total_seconds = std::chrono::duration<double>(total_end - total_start).count();
            std::cout << "compute_seconds=" << compute_seconds << '\n';
            std::cout << "total_seconds=" << total_seconds << '\n';
            print_metrics(metrics);
            return 0;
        }

        if (!gpu_available()) {
            std::cerr << "No CUDA device found. Use --mode cpu for CPU-only runs.\n";
            return 2;
        }

        if (mode == "gpu") {
            const auto compute_start = std::chrono::steady_clock::now();
            const DeviceMetrics device_metrics = run_gpu_kernel(records, threshold, block_size);
            const auto compute_end = std::chrono::steady_clock::now();
            const auto total_end = std::chrono::steady_clock::now();
            const double compute_seconds = std::chrono::duration<double>(compute_end - compute_start).count();
            const double total_seconds = std::chrono::duration<double>(total_end - total_start).count();
            std::cout << "compute_seconds=" << compute_seconds << '\n';
            std::cout << "total_seconds=" << total_seconds << '\n';
            print_metrics(to_metrics(device_metrics));
            return 0;
        }

        if (mode == "compare") {
            double cpu_compute_seconds = 0.0;
            const Metrics cpu_metrics = run_cpu_with_timing(records, threshold, cpu_compute_seconds);

            const auto gpu_start = std::chrono::steady_clock::now();
            const DeviceMetrics device_metrics = run_gpu_kernel(records, threshold, block_size);
            const auto gpu_end = std::chrono::steady_clock::now();
            const double gpu_compute_seconds = std::chrono::duration<double>(gpu_end - gpu_start).count();
            const Metrics gpu_metrics = to_metrics(device_metrics);

            const auto total_end = std::chrono::steady_clock::now();
            const double total_seconds = std::chrono::duration<double>(total_end - total_start).count();

            const bool matches = metrics_close(cpu_metrics, gpu_metrics, tolerance);
            std::cout << "cpu_compute_seconds=" << cpu_compute_seconds << '\n';
            std::cout << "gpu_compute_seconds=" << gpu_compute_seconds << '\n';
            std::cout << "total_seconds=" << total_seconds << '\n';
            std::cout << "compare_result=" << (matches ? "PASS" : "FAIL") << '\n';
            std::cout << "tolerance=" << tolerance << '\n';
            std::cout << "cpu_metrics:\n";
            print_metrics(cpu_metrics);
            std::cout << "gpu_metrics:\n";
            print_metrics(gpu_metrics);
            return matches ? 0 : 3;
        }

        std::cerr << "Unknown mode: " << mode << '\n';
        print_usage();
        return 1;
    } catch (const std::exception& exc) {
        std::cerr << "CUDA benchmark failed: " << exc.what() << '\n';
        return 1;
    }
}
