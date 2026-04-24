#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cuda_showcase
{

    constexpr int kCategoryCount = 8;
    constexpr const char *kCategoryNames[kCategoryCount] = {
        "disinformation",
        "harassment",
        "fraud",
        "cybercrime",
        "copyright",
        "hate_speech",
        "drugs",
        "sexual_content",
    };

    struct Record
    {
        int category = 0;
        float score = 0.0f;
        int iterations = 0;
        int success = 0;
    };

    struct Metrics
    {
        std::int64_t total_records = 0;
        std::int64_t success_count = 0;
        std::int64_t iteration_sum = 0;
        float score_sum = 0.0f;
        float max_score = 0.0f;
        std::array<std::int64_t, kCategoryCount> category_counts{};
        std::array<float, kCategoryCount> category_score_sums{};
    };

    inline std::string trim(std::string value)
    {
        auto not_space = [](unsigned char ch)
        { return !std::isspace(ch); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
        value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
        return value;
    }

    inline std::vector<std::string> split_csv_line(const std::string &line)
    {
        std::vector<std::string> parts;
        std::string current;
        bool in_quotes = false;

        for (char ch : line)
        {
            if (ch == '"')
            {
                in_quotes = !in_quotes;
            }
            else if (ch == ',' && !in_quotes)
            {
                parts.push_back(trim(current));
                current.clear();
            }
            else
            {
                current.push_back(ch);
            }
        }
        parts.push_back(trim(current));

        for (auto &part : parts)
        {
            if (part.size() >= 2 && part.front() == '"' && part.back() == '"')
            {
                part = part.substr(1, part.size() - 2);
            }
        }
        return parts;
    }

    inline std::vector<Record> load_records_from_csv(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open input file: " + path);
        }

        std::string header;
        if (!std::getline(file, header))
        {
            throw std::runtime_error("Input file is empty: " + path);
        }

        std::vector<Record> records;
        std::string line;
        while (std::getline(file, line))
        {
            line = trim(line);
            if (line.empty())
            {
                continue;
            }

            const auto parts = split_csv_line(line);
            if (parts.size() < 7)
            {
                throw std::runtime_error("Malformed row in input file: " + line);
            }

            Record record;
            record.category = std::stoi(parts[2]);
            record.score = std::stof(parts[3]);
            record.iterations = std::stoi(parts[5]);
            record.success = std::stoi(parts[6]);

            if (record.category < 0 || record.category >= kCategoryCount)
            {
                throw std::runtime_error("Category index out of range in input row: " + line);
            }

            records.push_back(record);
        }

        if (records.empty())
        {
            throw std::runtime_error("No records were loaded from input file: " + path);
        }

        return records;
    }

    inline Metrics compute_metrics_cpu(const std::vector<Record> &records, float success_threshold)
    {
        Metrics metrics;
        metrics.total_records = static_cast<std::int64_t>(records.size());
        metrics.max_score = 0.0f;

        for (const auto &record : records)
        {
            metrics.iteration_sum += record.iterations;
            metrics.score_sum += record.score;
            metrics.max_score = std::max(metrics.max_score, record.score);
            metrics.category_counts[static_cast<std::size_t>(record.category)] += 1;
            metrics.category_score_sums[static_cast<std::size_t>(record.category)] += record.score;
            if (record.success || record.score >= success_threshold)
            {
                metrics.success_count += 1;
            }
        }

        return metrics;
    }

    inline void print_metrics(const Metrics &metrics)
    {
        std::cout << "records=" << metrics.total_records << '\n';
        std::cout << "successes=" << metrics.success_count << '\n';
        std::cout << "iteration_sum=" << metrics.iteration_sum << '\n';
        std::cout << std::fixed << std::setprecision(6);
        std::cout << "score_sum=" << metrics.score_sum << '\n';
        std::cout << "max_score=" << metrics.max_score << '\n';
        for (int i = 0; i < kCategoryCount; ++i)
        {
            const auto count = metrics.category_counts[static_cast<std::size_t>(i)];
            const auto sum = metrics.category_score_sums[static_cast<std::size_t>(i)];
            const float average = count > 0 ? sum / static_cast<float>(count) : 0.0f;
            std::cout << "category[" << i << "]=" << kCategoryNames[i]
                      << ",count=" << count
                      << ",score_sum=" << sum
                      << ",avg_score=" << average << '\n';
        }
    }

    inline bool metrics_close(const Metrics &lhs, const Metrics &rhs, float tolerance)
    {
        if (lhs.total_records != rhs.total_records ||
            lhs.success_count != rhs.success_count ||
            lhs.iteration_sum != rhs.iteration_sum)
        {
            return false;
        }

        const auto close_float = [tolerance](float a, float b)
        {
            return std::abs(a - b) <= tolerance;
        };

        if (!close_float(lhs.score_sum, rhs.score_sum) || !close_float(lhs.max_score, rhs.max_score))
        {
            return false;
        }

        for (int i = 0; i < kCategoryCount; ++i)
        {
            if (lhs.category_counts[static_cast<std::size_t>(i)] != rhs.category_counts[static_cast<std::size_t>(i)])
            {
                return false;
            }
            if (!close_float(lhs.category_score_sums[static_cast<std::size_t>(i)], rhs.category_score_sums[static_cast<std::size_t>(i)]))
            {
                return false;
            }
        }

        return true;
    }

} // namespace cuda_showcase
