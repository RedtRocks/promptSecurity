#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

struct Row {
    float score;
    int iterations;
    int success;
};

static float harden_score(float score, int iterations, int success) {
    float value = score;
    const float drift = 1.0005f + 0.0001f * static_cast<float>(iterations);
    const float bias = success ? 0.00025f : -0.00015f;
    for (int pass = 0; pass < 256; ++pass) {
        value = value * drift + bias;
        value -= std::floor(value);
    }
    return value;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: ./cpu_metrics <csv_file>\n";
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

    std::vector<Row> rows;
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

        rows.push_back({score, iterations, success});
    }
    const auto load_end = std::chrono::steady_clock::now();

    if (rows.empty()) {
        std::cerr << "No data rows found\n";
        return 1;
    }

    const auto compute_start = std::chrono::steady_clock::now();
    int total_rows = 0;
    int success_count = 0;
    float score_sum = 0.0f;
    float max_score = 0.0f;

    for (const Row& row : rows) {
        const float hardened = harden_score(row.score, row.iterations, row.success);
        total_rows += 1;
        success_count += row.success;
        score_sum += hardened;
        max_score = std::max(max_score, hardened);
    }
    const auto compute_end = std::chrono::steady_clock::now();
    const auto total_end = std::chrono::steady_clock::now();

    const double load_seconds = std::chrono::duration<double>(load_end - load_start).count();
    const double compute_seconds = std::chrono::duration<double>(compute_end - compute_start).count();
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
