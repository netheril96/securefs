#include "../test_common.h"
#include "myutils.h"
#include "win/nt_directory_iterator.h"
#include "win/nt_exception.h"
#include "win/smart_handle.h"

#include <algorithm>
#include <doctest/doctest.h>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <Windows.h>

namespace securefs
{
TEST_CASE("NT directory iterator")
{
    auto temp_dir = OSService::temp_name("tmp/", ".ntdir");
    OSService::get_default().mkdir(temp_dir, 0700);

    HANDLE h = CreateFileW(widen_string(temp_dir).c_str(),
                           FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS,
                           NULL);
    if (h == INVALID_HANDLE_VALUE)
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", widen_string(temp_dir));

    UniqueHandle h_guard(h);

    SUBCASE("Empty directory")
    {
        securefs::NTDirectoryIterator it(h);
        // The directory contains '.' and '..', so it is not empty from the iterator's perspective
        auto entry1 = it.next();
        REQUIRE(entry1 != nullptr);
        CHECK(std::wstring_view(entry1->FileName, entry1->FileNameLength / sizeof(wchar_t))
              == L".");

        auto entry2 = it.next();
        REQUIRE(entry2 != nullptr);
        CHECK(std::wstring_view(entry2->FileName, entry2->FileNameLength / sizeof(wchar_t))
              == L"..");

        CHECK(it.next() == nullptr);
    }

    SUBCASE("One file")
    {
        std::string file_path = temp_dir + "\\a.txt";
        HANDLE hFile = CreateFileW(
            widen_string(file_path).c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        REQUIRE(hFile != INVALID_HANDLE_VALUE);
        CloseHandle(hFile);

        securefs::NTDirectoryIterator it(h);
        std::vector<std::wstring> names;
        while (auto entry = it.next())
        {
            names.emplace_back(entry->FileName, entry->FileNameLength / sizeof(wchar_t));
        }
        std::sort(names.begin(), names.end());

        CHECK(names == std::vector<std::wstring>{L".", L"..", L"a.txt"});
    }

    SUBCASE("Multiple files and directories")
    {
        std::vector<std::wstring> names = {L"a", L"b", L"c", L"d", L"e"};
        for (const auto& name : names)
        {
            HANDLE hFile = CreateFileW(
                widen_string(absl::StrCat(temp_dir, "\\", narrow_string(name))).c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_NEW,
                0,
                NULL);
            REQUIRE(hFile != INVALID_HANDLE_VALUE);
            CloseHandle(hFile);
        }
        REQUIRE(CreateDirectoryW(widen_string(temp_dir + "\\subdir").c_str(), NULL));
        names.push_back(L"subdir");
        names.push_back(L".");
        names.push_back(L"..");

        std::vector<std::wstring> found_names;
        securefs::NTDirectoryIterator it(h);
        while (auto entry = it.next())
        {
            found_names.emplace_back(entry->FileName, entry->FileNameLength / sizeof(wchar_t));
        }
        std::sort(names.begin(), names.end());
        std::sort(found_names.begin(), found_names.end());

        CHECK(names == found_names);

        SUBCASE("Rewind works")
        {
            it.rewind();
            std::vector<std::wstring> found_names2;
            while (auto entry = it.next())
            {
                found_names2.emplace_back(entry->FileName, entry->FileNameLength / sizeof(wchar_t));
            }
            std::sort(found_names2.begin(), found_names2.end());
            CHECK(names == found_names2);
        }
    }
}
}    // namespace securefs
