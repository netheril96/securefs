#include "test_common.h"

namespace securefs
{
namespace
{
    TEST_CASE("Test symlink, stat, and readlink")
    {
        auto& os_service = OSService::get_default();

        // Create a temporary file and symlink
        auto target_file = OSService::temp_name("tmp/", ".target");
        auto symlink_file = OSService::temp_name("tmp/", ".symlink");

        // Ensure cleanup
        DEFER({
            os_service.remove_file_nothrow(symlink_file);
            os_service.remove_file_nothrow(target_file);
        });

        // Write to the target file
        auto target_stream = os_service.open_file_stream(target_file, O_WRONLY | O_CREAT, 0644);
        const char* content = "Hello, SecureFS!";
        target_stream->write(content, 0, strlen(content));
        target_stream.reset();

        // Create a symlink
        os_service.symlink(target_file, symlink_file);

        // Test stat on the symlink
        fuse_stat symlink_stat;
        REQUIRE(os_service.stat(symlink_file, &symlink_stat));
        CHECK((symlink_stat.st_mode & S_IFMT) == S_IFLNK);

        // Test readlink
        char buffer[1024];
        auto link_size = os_service.readlink(symlink_file, buffer, sizeof(buffer));
        REQUIRE(link_size > 0);
        CHECK(std::string(buffer, link_size) == target_file);
    }

}    // namespace
}    // namespace securefs
