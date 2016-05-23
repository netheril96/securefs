#ifndef _WIN32
#include "catch.hpp"
#include "commands.h"
#include "myutils.h"
#include "platform.h"

#include <format.h>

#include <chrono>
#include <thread>
#include <vector>

#include <signal.h>
#include <unistd.h>

using namespace securefs;

namespace
{
class SecurefsTestControl
{
private:
    pid_t mount_pid = -1;

    const std::chrono::milliseconds WAIT_DURATION{100};

public:
    std::string mount_dir, data_dir, password, version_string;

    void create()
    {
        const char* arguments[] = {process_name.c_str(),
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
        std::this_thread::sleep_for(WAIT_DURATION);
        mount_pid = fork();
        REQUIRE(mount_pid >= 0);
        if (mount_pid == 0)
        {
            execlp(process_name.c_str(),
                   process_name.c_str(),
                   "mount",
                   data_dir.c_str(),
                   mount_dir.c_str(),
                   "--pass",
                   password.c_str(),
                   (const char*)nullptr);
            FAIL("execlp ourselves fails: " << sane_strerror(errno));
        }
        else
        {
            std::this_thread::sleep_for(WAIT_DURATION);
        }
    }

    void unmount()
    {
        if (mount_pid < 0)
            return;
        std::this_thread::sleep_for(WAIT_DURATION);
        // Unmounting too quickly will cause errors
        // This is unavoidable due to the communication design of FUSE
        if (kill(mount_pid, SIGINT) < 0)
            FAIL("Sending SIGINT to child fails: " << sane_strerror(errno));
        std::this_thread::sleep_for(WAIT_DURATION);
        mount_pid = -1;
    }

    SecurefsTestControl() {}
    ~SecurefsTestControl()
    {
        try
        {
            unmount();
        }
        catch (...)
        {
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
    bool data_unchanged = (new_buffer == random_buffer);
    REQUIRE(data_unchanged);
    stream.reset();
    control.unmount();
}

TEST_CASE("Integration test")
{
    test_securefs_fs_version(1);
    test_securefs_fs_version(2);
}

#endif