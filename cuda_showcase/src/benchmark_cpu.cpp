#include "common.hpp"

#include <chrono>
#include <string>

using namespace cuda_showcase;

struct CpuResult
{
    Metrics metrics;
    double load_seconds = 0.0;
    double compute_seconds = 0.0;
    double total_seconds = 0.0;
};

static void print_usage()
{
    std::cout << "Usage: benchmark_cpu --input <file> [--threshold <float>]\n";
}

static CpuResult run_cpu_benchmark(const std::string &input_path, float threshold)
{
    const auto total_start = std::chrono::steady_clock::now();

    const auto load_start = std::chrono::steady_clock::now();
    const auto records = load_records_from_csv(input_path);
    const auto load_end = std::chrono::steady_clock::now();

    const auto compute_start = std::chrono::steady_clock::now();
    const auto metrics = compute_metrics_cpu(records, threshold);
    const auto compute_end = std::chrono::steady_clock::now();
    const auto total_end = std::chrono::steady_clock::now();

    CpuResult result;
    result.metrics = metrics;
    result.load_seconds = std::chrono::duration<double>(load_end - load_start).count();
    result.compute_seconds = std::chrono::duration<double>(compute_end - compute_start).count();
    result.total_seconds = std::chrono::duration<double>(total_end - total_start).count();
    return result;
}

int main(int argc, char **argv)
{
    std::string input_path;
    float threshold = 0.95f;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--input" && i + 1 < argc)
        {
            input_path = argv[++i];
        }
        else if (arg == "--threshold" && i + 1 < argc)
        {
            threshold = std::stof(argv[++i]);
        }
        else if (arg == "--help" || arg == "-h")
        {
            print_usage();
            return 0;
        }
        else
        {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            print_usage();
            return 1;
        }
    }

    if (input_path.empty())
    {
        std::cerr << "Missing required --input argument\n";
        print_usage();
        return 1;
    }

    try
    {
        const auto result = run_cpu_benchmark(input_path, threshold);
        std::cout << "mode=cpu\n";
        std::cout << "input=" << input_path << '\n';
        std::cout << "threshold=" << threshold << '\n';
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "load_seconds=" << result.load_seconds << '\n';
        std::cout << "compute_seconds=" << result.compute_seconds << '\n';
        std::cout << "total_seconds=" << result.total_seconds << '\n';
        print_metrics(result.metrics);
    }
    catch (const std::exception &exc)
    {
        std::cerr << "CPU benchmark failed: " << exc.what() << '\n';
        return 1;
    }

    return 0;
}
