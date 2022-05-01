#ifdef _WIN32
#include "catch.hpp"
#include "platform.h"

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
#endif
