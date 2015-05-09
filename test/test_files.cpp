#ifdef UNIT_TEST
#include "catch.hpp"
#include "files.h"
#include "file_table.h"

#include <string.h>
#include <errno.h>
#include <vector>
#include <algorithm>
#include <set>

#include <fcntl.h>
#include <unistd.h>

TEST_CASE("File table")
{
    using namespace securefs;
    char dir_template[] = "/tmp/securefs_file_table.XXXXXXX";
    mkdtemp(dir_template);

    key_type master_key;
    id_type null_id, file_id;
    memset(master_key.data(), 0xFF, master_key.size());
    memset(null_id.data(), 0, null_id.size());
    memset(file_id.data(), 0xEE, file_id.size());
    const char* xattr_name = "com.apple.FinderInfo...";
    const securefs::PODArray<char, 32> xattr_value(0x11);

    {
        int tmp_fd = ::open(dir_template, O_RDONLY);
        REQUIRE(tmp_fd >= 0);
        FileTable table(tmp_fd, master_key, 0);
        auto dir = dynamic_cast<Directory*>(table.create_as(null_id, FileBase::DIRECTORY));
        dir->add_entry(".", null_id, FileBase::DIRECTORY);
        dir->add_entry("..", null_id, FileBase::DIRECTORY);
        dir->add_entry("hello", file_id, FileBase::REGULAR_FILE);
        dir->setxattr(xattr_name, xattr_value.data(), xattr_value.size(), 0);
        table.close(dir);
        ::close(tmp_fd);
    }

    {
        int tmp_fd = ::open(dir_template, O_RDONLY);
        REQUIRE(tmp_fd >= 0);
        FileTable table(tmp_fd, master_key, 0);
        auto dir = dynamic_cast<Directory*>(table.open_as(null_id, FileBase::DIRECTORY));
        securefs::PODArray<char, 32> xattr_test_value(0);
        dir->getxattr(xattr_name, xattr_test_value.data(), xattr_test_value.size());
        REQUIRE(xattr_value == xattr_test_value);

        std::set<std::string> filenames;
        dir->iterate_over_entries([&](const std::string& fn, const id_type&, int)
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
        table.close(dir);
        ::close(tmp_fd);
    }
}
#endif
