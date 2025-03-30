#include "test_common.h"

namespace securefs
{
namespace
{
    constexpr std::string_view kLongFileNameExample = u8"🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️";
    std::string construct_long_filename()
    {
        return absl::StrCat(
            kLongFileNameExample, "/", kLongFileNameExample, "/", kLongFileNameExample);
    }

    TEST_CASE("Test symlink, stat, and readlink")
    {
        auto& os_service = OSService::get_default();

        // Create a temporary file and symlink
        auto target_file = OSService::temp_name("tmp/", construct_long_filename());
        auto symlink_file = OSService::temp_name("tmp/", ".symlink");

        // Ensure cleanup
        DEFER({ os_service.remove_file_nothrow(symlink_file); });

        // Create a symlink
        os_service.symlink(target_file, symlink_file);

        // Test stat on the symlink
        fuse_stat symlink_stat;
        REQUIRE(os_service.stat(symlink_file, &symlink_stat));
        CHECK((symlink_stat.st_mode & S_IFMT) == S_IFLNK);

        // Test readlink
        char buffer[65535];
        auto link_size = os_service.readlink(symlink_file, buffer, sizeof(buffer));
        REQUIRE(link_size == symlink_stat.st_size);
        CHECK(std::string(buffer, link_size) == target_file);
    }

}    // namespace
}    // namespace securefs
