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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace securefs;

static bool is_mounted(const std::string& path)
{
    auto parent_path = path + "/..";
    struct stat parent_st, st;
    if (stat(path.c_str(), &st) < 0 || stat(parent_path.c_str(), &parent_st) < 0)
    {
        if (errno == ENXIO)
            return false;    // "Device not configured" because fuse mounting isn't fully
                             // initialized
        throw POSIXException(errno, "stat");
    }
    if (!S_ISDIR(parent_st.st_mode) || !S_ISDIR(st.st_mode))
    {
        throw OSException(ENOTDIR);
    }
    return st.st_dev != parent_st.st_dev;
}

namespace
{
class SecurefsTestControl
{
private:
    pid_t mount_pid = -1;

    void sleep_while() { std::this_thread::sleep_for(std::chrono::nanoseconds(100000)); }

    void sleep_until_mounted()
    {
        do
        {
            sleep_while();
        } while (!is_mounted(mount_dir));
    }

    void sleep_until_unmounted()
    {
        do
        {
            sleep_while();
        } while (is_mounted(mount_dir));
    }

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
        if (mount_pid > 0)
            return;
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
            throw POSIXException(errno, "execlp");
        }
        else
        {
            sleep_until_mounted();
        }
    }

    void unmount()
    {
        if (mount_pid < 0)
            return;
        if (kill(mount_pid, SIGINT) < 0)
            throw POSIXException(errno, "kill");
        while (waitpid(mount_pid, nullptr, 0) < 0)
        {
            if (errno != EINTR)
                throw POSIXException(errno, "waitpid");
        }
        sleep_until_unmounted();
        mount_pid = -1;
    }

    SecurefsTestControl() {}
    ~SecurefsTestControl()
    {
        if (mount_pid < 0)
            return;
        (void)kill(mount_pid, SIGINT);
        (void)waitpid(mount_pid, nullptr, WNOHANG);
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