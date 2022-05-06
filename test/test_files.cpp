#include "catch.hpp"
#include "crypto.h"
#include "exceptions.h"
#include "file_table.h"
#include "files.h"

#include <algorithm>
#include <errno.h>
#include <set>
#include <string.h>
#include <vector>

static void test_file_table(unsigned max_padding_size)
{
    using namespace securefs;
    auto base_dir = OSService::temp_name("tmp/file_table", ".dir");
    OSService::get_default().ensure_directory(base_dir, 0755);

    key_type master_key(0x48);
    id_type null_id, file_id;
    generate_random(file_id.data(), file_id.size());
    const char* xattr_name = "com.apple.FinderInfo...";
    const securefs::PODArray<char, 32> xattr_value(0x11);

    {
        auto root = std::make_shared<OSService>(base_dir);
        ShardedFileTableImpl table(2, root, master_key, 0, 3000, 16, max_padding_size);
        auto dir = dynamic_cast<Directory*>(table.create_as(null_id, FileBase::DIRECTORY));
        DEFER(table.close(dir));

        FileLockGuard flg(*dir);
        table.create_as(file_id, FileBase::REGULAR_FILE);
        dir->add_entry(".", null_id, FileBase::DIRECTORY);
        dir->add_entry("..", null_id, FileBase::DIRECTORY);
        dir->add_entry("hello", file_id, FileBase::REGULAR_FILE);
        try
        {
            dir->setxattr(xattr_name, xattr_value.data(), xattr_value.size(), 0);
        }
        catch (const securefs::ExceptionBase& e)
        {
            REQUIRE(e.error_number() == ENOTSUP);
        }
    }

    {
        auto all_ids = find_all_ids(base_dir.c_str());
        REQUIRE(all_ids.size() == 2);
        REQUIRE(all_ids.find(null_id) != all_ids.end());
        REQUIRE(all_ids.find(file_id) != all_ids.end());
    }

    {
        auto root = std::make_shared<OSService>(base_dir);
        FileTableImpl table(2, root, master_key, 0, 3000, 16, max_padding_size);
        auto dir = dynamic_cast<Directory*>(table.open_as(null_id, FileBase::DIRECTORY));
        DEFER(table.close(dir));

        securefs::PODArray<char, 32> xattr_test_value(0);
        try
        {
            FileLockGuard flg(*dir);
            dir->getxattr(xattr_name, xattr_test_value.data(), xattr_test_value.size());
            REQUIRE(xattr_value == xattr_test_value);
        }
        catch (const securefs::ExceptionBase& e)
        {
            REQUIRE(e.error_number() == ENOTSUP);
        }

        std::set<std::string> filenames;
        FileLockGuard flg(*dir);
        dir->iterate_over_entries(
            [&](const std::string& fn, const id_type&, int)
            {
                filenames.insert(fn);
                return true;
            });
        REQUIRE((filenames == decltype(filenames){".", "..", "hello"}));
        id_type id;
        int type;
        dir->get_entry("hello", id, type);
        REQUIRE(memcmp(id.data(), file_id.data(), id.size()) == 0);
        bool is_regular_file = type == FileBase::REGULAR_FILE;
        REQUIRE(is_regular_file);
    }
}

TEST_CASE("File table")
{
    test_file_table(0);
    test_file_table(255);
}
