#include "platform.h"
#include "win/nt_exception.h"
#include "win/nt_stream.h"

#include "../test_streams.h"

#include <doctest/doctest.h>

namespace securefs
{
TEST_CASE("Test NT stream")
{
    auto filename = OSService::temp_name("tmp/", ".stream");
    HANDLE h = CreateFileW(widen_string(filename).c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", widen_string(filename));
    }
    NTStream stream{UniqueHandle{h}};
    test_streams(stream, 4000);
}
}    // namespace securefs
