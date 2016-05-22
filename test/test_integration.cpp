#ifndef _WIN32
#include "catch.hpp"
#include "commands.h"
#include "myutils.h"
#include "platform.h"

#include "format.h"

#include <vector>

#include <signal.h>
#include <unistd.h>

using namespace securefs;

namespace
{
class SecurefsTestControl
{
private:
    bool mounted = false;

    void wait_exit(pid_t pid)
    {
        int status;
        REQUIRE(waitpid(pid, &status, 0) != -1);
        REQUIRE(WIFEXITED(status));
        REQUIRE(WEXITSTATUS(status) == 0);
    }

public:
    std::string mount_dir, data_dir, password, version_string;

    void create()
    {
        const char* arguments[] = {"securefs",
                                   "create",
                                   data_dir.c_str(),
                                   "--ver",
                                   version_string.c_str(),
                                   "--pass",
                                   password.c_str(),
                                   "--rounds",
                                   "1",
                                   nullptr};
        int argc = sizeof(arguments) / sizeof(arguments[0]) - 1;
        REQUIRE(commands_main(argc, arguments) == 0);
    }

    void mount()
    {
        pid_t pid = fork();
        REQUIRE(pid >= 0);

        if (pid == 0)
        {
            const char* arguments[] = {"securefs",
                                       "create",
                                       data_dir.c_str(),
                                       "--ver",
                                       version_string.c_str(),
                                       "--pass",
                                       password.c_str(),
                                       nullptr};
            int argc = sizeof(arguments) / sizeof(arguments[0]) - 1;
            REQUIRE(commands_main(argc, arguments) == 0);
        }
        else
        {
            wait_exit(pid);
            mounted = true;
        }
    }

    void unmount()
    {
        pid_t pid = fork();
        REQUIRE(pid >= 0);

        if (pid == 0)
        {
#ifdef __APPLE__
            int rc = execlp("umount", "umount", mount_dir.c_str(), (const char*)nullptr);
#else
            int rc
                = execlp("fusermount", "fusermount", "-u", mount_dir.c_str(), (const char*)nullptr);
#endif
            REQUIRE(false);
        }
        else
        {
            wait_exit(pid);

            mounted = false;
        }
    }

    SecurefsTestControl() {}
    ~SecurefsTestControl()
    {
        if (mounted)
        {
            try
            {
                unmount();
            }
            catch (...)
            {
            }
        }
    }
};
}

static void test_securefs_fs_version(int version)
{
    FileSystemService service;

    SecurefsTestControl control;
    control.mount_dir = service.temp_name("tmp/mount.", ".dir");
    control.data_dir = service.temp_name("tmp/data.", ".dir");
    control.password = "madoka";
    control.version_string = fmt::format("{}", version);

    service.ensure_directory(control.mount_dir, 0755);
    service.ensure_directory(control.data_dir, 0755);

    control.create();

    control.mount();
    std::vector<byte> random_buffer(2000000);
    generate_random(random_buffer.data(), random_buffer.size());
    auto random_filename = control.mount_dir + "/rnd";
    auto stream = service.open_file_stream(random_filename, O_WRONLY | O_CREAT | O_EXCL, 0644);
    stream->write(random_buffer.data(), 0, random_buffer.size());
    stream.reset();
    control.unmount();

    control.mount();
    stream = service.open_file_stream(random_filename, O_RDONLY, 0644);
    std::vector<byte> new_buffer(random_buffer.size());
    REQUIRE(stream->read(new_buffer.data(), 0, new_buffer.size()) == new_buffer.size());
    REQUIRE(new_buffer == random_buffer);
    control.unmount();
}

TEST_CASE("Integration test")
{
    test_securefs_fs_version(1);
    test_securefs_fs_version(2);
}

#endif