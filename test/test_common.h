#pragma once

#include <absl/strings/escaping.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_join.h>
#include <absl/strings/string_view.h>
#include <doctest/doctest.h>

#include <random>
#include <vector>

std::mt19937& get_random_number_engine();

inline doctest::String to_doc_str(absl::string_view view)
{
    return {view.data(), static_cast<doctest::String::size_type>(view.size())};
}

template <>
struct doctest::StringMaker<absl::string_view>
{
    static doctest::String convert(const absl::string_view& value) { return to_doc_str(value); }
};

template <>
struct doctest::StringMaker<std::vector<std::string>>
{
    static doctest::String convert(std::vector<std::string> value)
    {
        for (auto&& str : value)
        {
            str = absl::Utf8SafeCEscape(str);
        }
        return to_doc_str(absl::StrCat("[", absl::StrJoin(value, ", "), "]"));
    }
};
