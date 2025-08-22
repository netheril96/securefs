#pragma once

#include "fuse_high_level_ops_base.h"
#include "platform.h"

#include <absl/strings/escaping.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_join.h>
#include <doctest/doctest.h>
#include <string_view>

#include <random>
#include <vector>

std::mt19937& get_random_number_engine();

inline doctest::String to_doc_str(std::string_view view)
{
    return {view.data(), static_cast<doctest::String::size_type>(view.size())};
}

template <>
struct doctest::StringMaker<std::string_view>
{
    static doctest::String convert(const std::string_view& value) { return to_doc_str(value); }
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

#ifdef _WIN32

template <>
struct doctest::StringMaker<std::wstring_view>
{
    static doctest::String convert(const std::wstring_view& value)
    {
        return to_doc_str(securefs::narrow_string(value));
    }
};

template <>
struct doctest::StringMaker<std::vector<std::wstring>>
{
    static doctest::String convert(const std::vector<std::wstring>& value)
    {
        std::vector<std::string> converted;
        converted.reserve(value.size());
        for (auto&& str : value)
        {
            converted.emplace_back(securefs::narrow_string(str));
        }
        return to_doc_str(absl::StrCat("[", absl::StrJoin(converted, ", "), "]"));
    }
};
#endif

namespace securefs::testing
{

enum class CaseSensitivity
{
    CaseSensitive,
    CaseInsensitive
};

enum class ResolveSymlinks
{
    NO,
    YES
};

void test_fuse_ops(FuseHighLevelOpsBase& ops,
                   OSService& repo_root,
                   CaseSensitivity case_sensitivity = CaseSensitivity::CaseSensitive,
                   ResolveSymlinks resolve_symlinks = ResolveSymlinks::NO);
}    // namespace securefs::testing
