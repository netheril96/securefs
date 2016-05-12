#ifndef _WIN32

#include "exceptions.h"
#include "format.h"
#include "platform.h"
#include "streams.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace securefs
{
class UnixFileStream final : public FileStream
{
private:
    int m_fd;
    length_type m_size;

public:
    explicit UnixFileStream(int fd) : m_fd(fd)
    {
        if (fd < 0)
            throw OSException(EBADF);
        struct stat st;
        int rc = ::fstat(m_fd, &st);
        if (rc < 0)
            throw OSException(errno);
        m_size = st.st_size;
    }

    ~UnixFileStream() { ::close(m_fd); }

    int get_native_handle() noexcept override { return m_fd; }

    void fsync() override
    {
        int rc = ::fsync(m_fd);
        if (rc < 0)
            throw UnderlyingOSException(errno, "fsync");
    }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            throw UnderlyingOSException(errno, "pread");
        return rc;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            throw UnderlyingOSException(errno, "pwrite");
        if (static_cast<length_type>(rc) != length)
            throw OSException(EIO);
        if (offset + length > m_size)
            m_size = offset + length;
    }

    void flush() override {}

    void resize(length_type new_length) override
    {
        auto rc = ::ftruncate(m_fd, new_length);
        if (rc < 0)
            UnderlyingOSException(errno, "truncate");
        m_size = new_length;
    }

    length_type size() const override { return m_size; }

    bool is_sparse() const noexcept override { return true; }

    void utimens(const struct timespec ts[2]) override
    {
        int rc;
#if _XOPEN_SOURCE >= 700 || _POSIX_C_SOURCE >= 200809L
        rc = ::futimens(m_fd, ts);
#else
        if (!ts)
            rc = ::futimes(m_fd, nullptr);
        else
        {
            struct timeval time_values[2];
            for (size_t i = 0; i < 2; ++i)
            {
                time_values[i].tv_sec = ts[i].tv_sec;
                time_values[i].tv_usec
                    = static_cast<decltype(time_values[i].tv_usec)>(ts[i].tv_nsec / 1000);
            }
            rc = ::futimes(m_fd, time_values);
        }
#endif
        if (rc < 0)
            throw UnderlyingOSException(errno, "utimens");
    }
};

class RootDirectory::Impl
{
public:
    std::string dir_name;
    int dir_fd;
};

RootDirectory::~RootDirectory() {}

RootDirectory::RootDirectory(const std::string& path, bool readonly) : impl(new Impl())
{
    impl->dir_name = path;
    int dir_fd = ::open(path.c_str(), readonly ? O_RDONLY : O_RDWR);
    if (dir_fd < 0)
        throw UnderlyingOSException(errno, fmt::format("Opening directory {}", path));
    impl->dir_fd = dir_fd;
}

std::shared_ptr<FileStream>
RootDirectory::open_file_stream(const std::string& path, int flags, unsigned mode)
{
    int fd = ::openat(impl->dir_fd, path.c_str(), flags, mode);
    if (fd < 0)
        throw UnderlyingOSException(
            errno, fmt::format("Opening {}/{} with flags {}", impl->dir_name, path, flags));
    return std::make_shared<UnixFileStream>(fd);
}

bool RootDirectory::remove_file(const std::string& path) noexcept
{
    return ::unlinkat(impl->dir_fd, path.c_str(), 0) == 0;
}

bool RootDirectory::remove_directory(const std::string& path) noexcept
{
    return ::unlinkat(impl->dir_fd, path.c_str(), AT_REMOVEDIR);
}

void RootDirectory::lock()
{
    int rc = ::flock(impl->dir_fd, LOCK_NB | LOCK_EX);
    if (rc < 0)
        throw UnderlyingOSException(
            errno, fmt::format("Fail to obtain exclusive lock on {}", impl->dir_name));
}

void RootDirectory::ensure_directory(const std::string& path, unsigned mode)
{
    int rc = ::mkdirat(impl->dir_fd, path.c_str(), mode);
    if (rc < 0 && errno != EEXIST)
        throw UnderlyingOSException(
            errno, fmt::format("Fail to create directory {}/{}", impl->dir_name, path));
}

void RootDirectory::statfs(struct statvfs* fs_info)
{
    int rc = ::fstatvfs(impl->dir_fd, fs_info);
    if (rc < 0)
        throw UnderlyingOSException(errno, "statvfs");
    fs_info->f_namemax = 255;
}

void RootDirectory::rename(const std::string& a, const std::string& b)
{
    int rc = ::rename(a.c_str(), b.c_str());
    if (rc < 0)
        throw UnderlyingOSException(
            errno,
            fmt::format("Renaming from {}/{} to {}/{}", impl->dir_name, a, impl->dir_name, b));
}

uint32_t getuid() noexcept { return ::getuid(); }
uint32_t getgid() noexcept { return ::getgid(); }
}
#endif