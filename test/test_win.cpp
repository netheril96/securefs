#include "myutils.h"
#include <string_view>
#ifdef _WIN32
#include "platform.h"
#include "test_common.h"

#include <doctest/doctest.h>    // IWYU pragma: keep

#include <random>
#include <string>
#include <vector>

#include <shellapi.h>    // For CommandLineToArgvW

using ::securefs::OSService;

TEST_CASE("Test windows path normalization")
{
    REQUIRE(OSService::concat_and_norm("", R"(C:\abc.txt)") == LR"(C:\abc.txt)");
    REQUIRE(OSService::concat_and_norm(R"(C:\Users)", R"(C:\abc.txt)") == LR"(C:\abc.txt)");
    REQUIRE(OSService::concat_and_norm(R"(C:\Users)", R"(\\server\share)") == LR"(\\server\share)");
    REQUIRE(OSService::concat_and_norm(R"(C:\Users)", R"(/cygwin)") == LR"(/cygwin)");
    REQUIRE(OSService::concat_and_norm(R"(C:\Users)", R"(👌🎍😍)") == LR"(\\?\C:\Users\👌🎍😍)");
    REQUIRE(OSService::concat_and_norm(R"(C:\Users)", R"(cygwin\..\abc\.\.\.)")
            == LR"(\\?\C:\Users\abc)");
    REQUIRE(OSService::concat_and_norm(R"(\\server\share\)", R"(cygwin\..\abc\.\.\.)")
            == LR"(\\server\share\abc)");
    REQUIRE(OSService::concat_and_norm(R"(\\?\\C:\Users\\\.//..)", R"(cygwin/)")
            == LR"(\\?\C:\cygwin)");
    REQUIRE(OSService::concat_and_norm(R"(\\?\C:\Users)", R"(cygwin/../c)")
            == LR"(\\?\C:\Users\c)");
    REQUIRE(OSService::concat_and_norm(R"(\\?\C:\Users)", R"(cygwin/./c)")
            == LR"(\\?\C:\Users\cygwin\c)");
    REQUIRE(OSService::concat_and_norm(R"(\\?\C:\Users)", R"(cygwin)")
            == LR"(\\?\C:\Users\cygwin)");
    REQUIRE(OSService::concat_and_norm(R"(\\?\UNC\server\share)", R"(a\b\c)")
            == LR"(\\?\UNC\server\share\a\b\c)");
    REQUIRE_THROWS(OSService::concat_and_norm("abc", "def"));
}

TEST_CASE("Test win_quote_argv with CommandLineToArgvW")
{
    auto& eng = get_random_number_engine();
    std::uniform_int_distribution<size_t> length_dist(0, 19);
    // Characters 1-127 are ASCII and single-byte in UTF-8.
    // They have the same representation in UTF-16 (as single 16-bit units).
    std::uniform_int_distribution<int> prob_dist(0, 2);    // 0 for special, 1 or 2 for general
    constexpr std::string_view special_chars = "'\"\\ \n\r\t\f\b\v";
    std::uniform_int_distribution<unsigned> char_dist(1, 127);
    std::uniform_int_distribution<size_t> special_char_idx_dist(0, special_chars.length() - 1);

    std::vector<std::string> original_args;
    original_args.reserve(3);

    for (int i = 0; i < 1000; ++i)
    {
        original_args.clear();
        for (int j = 0; j < 3; ++j)
        {
            size_t len = length_dist(eng);
            std::string arg_str;
            arg_str.reserve(len);
            for (size_t k = 0; k < len; ++k)
            {
                if (prob_dist(eng) == 0)
                {
                    // Choose from special characters
                    arg_str.push_back(special_chars[special_char_idx_dist(eng)]);
                }
                else
                {
                    arg_str.push_back(static_cast<char>(char_dist(eng)));
                }
            }
            original_args.push_back(std::move(arg_str));
        }

        std::string cmd_line_str_utf8;    // This will be UTF-8
        for (size_t j = 0; j < original_args.size(); ++j)
        {
            cmd_line_str_utf8 += OSService::win_quote_argv(original_args[j]);
            if (j < original_args.size() - 1)
            {
                cmd_line_str_utf8 += " ";
            }
        }

        std::wstring cmd_line_str_utf16 = securefs::widen_string(cmd_line_str_utf8);

        int argc_parsed = 0;
        LPWSTR* argvW = CommandLineToArgvW(cmd_line_str_utf16.c_str(), &argc_parsed);

        if (argvW == nullptr)
        {
            FAIL("CommandLineToArgvW failed with error: " << GetLastError() << " for command line: "
                                                          << cmd_line_str_utf8);
            continue;
        }
        DEFER(LocalFree((void*)argvW));

        REQUIRE(argc_parsed == static_cast<int>(original_args.size()));

        std::vector<std::string> parsed_args;
        parsed_args.reserve(argc_parsed);
        for (int k = 0; k < argc_parsed; ++k)
        {
            parsed_args.push_back(securefs::narrow_string(argvW[k]));
        }

        REQUIRE(parsed_args.size() == original_args.size());
        CHECK(parsed_args == original_args);
    }
}
#endif
