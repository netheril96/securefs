#include "exceptions.h"
#include "platform.h"
#include "streams.h"

#include <algorithm>
#include <vector>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -2
#endif

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
            throw POSIXException(errno, "fstat");
        m_size = st.st_size;
    }

    ~UnixFileStream() { ::close(m_fd); }

    void fsync() override
    {
        int rc = ::fsync(m_fd);
        if (rc < 0)
            throw POSIXException(errno, "fsync");
    }

    void fstat(struct stat* out) override
    {
        if (!out)
            throw OSException(EFAULT);

        if (::fstat(m_fd, out) < 0)
            throw POSIXException(errno, "fstat");
    }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            throw POSIXException(errno, "pread");
        return rc;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            throw POSIXException(errno, "pwrite");
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
            POSIXException(errno, "truncate");
        m_size = new_length;
    }

    length_type size() const override { return m_size; }

    bool is_sparse() const noexcept override { return true; }

    void utimens(const struct timespec ts[2]) override
    {
        int rc;
#ifdef HAS_FUTIMENS
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
            throw POSIXException(errno, "utimens");
    }

#ifdef __APPLE__

    void removexattr(const char* name) override
    {
        auto rc = ::fremovexattr(m_fd, name, 0);
        if (rc < 0)
            throw POSIXException(errno, "fremovexattr");
    }

    ssize_t getxattr(const char* name, void* value, size_t size) override
    {
        ssize_t rc = ::fgetxattr(m_fd, name, value, size, 0, 0);
        if (rc < 0)
            throw POSIXException(errno, "fgetxattr");
        return rc;
    }

    ssize_t listxattr(char* buffer, size_t size) override
    {
        auto rc = ::flistxattr(m_fd, buffer, size, 0);
        if (rc < 0)
            throw POSIXException(errno, "flistxattr");
        return rc;
    }

    void setxattr(const char* name, void* value, size_t size, int flags) override
    {
        auto rc = ::fsetxattr(m_fd, name, value, size, 0, flags);
        if (rc < 0)
            throw POSIXException(errno, "fsetxattr");
    }
#endif
};

class FileSystemService::Impl
{
public:
    std::string dir_name;
    int dir_fd;

    std::string norm_path(const std::string& path) const
    {
        if (dir_fd < 0)
            return path;
        if (path.size() > 0 && path[0] == '/')
            return path;
        return dir_name + '/' + path;
    }
};

FileSystemService::FileSystemService() : impl(new Impl()) { impl->dir_fd = AT_FDCWD; }

FileSystemService::~FileSystemService()
{
    if (impl->dir_fd >= 0)
        ::close(impl->dir_fd);
}

FileSystemService::FileSystemService(const std::string& path) : impl(new Impl())
{
    impl->dir_name = path;
    int dir_fd = ::open(path.c_str(), O_RDONLY);
    if (dir_fd < 0)
        throw POSIXException(errno, "Opening directory " + path);
    impl->dir_fd = dir_fd;
}

std::shared_ptr<FileStream>
FileSystemService::open_file_stream(const std::string& path, int flags, unsigned mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int fd = ::openat(impl->dir_fd, path.c_str(), flags, mode);
#else
    int fd = ::open(impl->norm_path(path).c_str(), flags, mode);
#endif
    if (fd < 0)
        throw POSIXException(
            errno, strprintf("Opening %s with flags %#o", impl->norm_path(path).c_str(), flags));
    return std::make_shared<UnixFileStream>(fd);
}

bool FileSystemService::remove_file(const std::string& path) const noexcept
{
#ifdef HAS_AT_FUNCTIONS
    return ::unlinkat(impl->dir_fd, path.c_str(), 0) == 0;
#else
    return ::unlink(impl->norm_path(path).c_str()) == 0;
#endif
}

bool FileSystemService::remove_directory(const std::string& path) const noexcept
{
#ifdef HAS_AT_FUNCTIONS
    return ::unlinkat(impl->dir_fd, path.c_str(), AT_REMOVEDIR) == 0;
#else
    return ::rmdir(impl->norm_path(path).c_str()) == 0;
#endif
}

void FileSystemService::lock() const
{
    int rc = ::flock(impl->dir_fd, LOCK_NB | LOCK_EX);
    if (rc < 0)
        throw POSIXException(
            errno, strprintf("Fail to obtain exclusive lock on %s", impl->dir_name.c_str()));
}

void FileSystemService::ensure_directory(const std::string& path, unsigned mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::mkdirat(impl->dir_fd, path.c_str(), mode);
#else
    int rc = ::mkdir(impl->norm_path(path).c_str(), mode);
#endif
    if (rc < 0 && errno != EEXIST)
        throw POSIXException(
            errno, strprintf("Fail to create directory %s", impl->norm_path(path).c_str()));
}

void FileSystemService::statfs(struct statvfs* fs_info) const
{
    int rc = ::fstatvfs(impl->dir_fd, fs_info);
    if (rc < 0)
        throw POSIXException(errno, "statvfs");
}

void FileSystemService::rename(const std::string& a, const std::string& b) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::renameat(impl->dir_fd, a.c_str(), impl->dir_fd, b.c_str());
#else
    int rc = ::rename(impl->norm_path(a).c_str(), impl->norm_path(b).c_str());
#endif
    if (rc < 0)
        throw POSIXException(errno,
                             strprintf("Renaming from %s to %s",
                                       impl->norm_path(a).c_str(),
                                       impl->norm_path(b).c_str()));
}

uint32_t FileSystemService::getuid() noexcept { return ::getuid(); }
uint32_t FileSystemService::getgid() noexcept { return ::getgid(); }

int FileSystemService::raise_fd_limit()
{
    struct rlimit rl;
    int rc = ::getrlimit(RLIMIT_NOFILE, &rl);
    if (rc < 0)
        throw POSIXException(errno, "getrlimit");

    rl.rlim_cur = 10240 * 16;
    do
    {
        rl.rlim_cur /= 2;
        rc = ::setrlimit(RLIMIT_NOFILE, &rl);
    } while (rc < 0 && rl.rlim_cur >= 1024);

    if (rc < 0)
        throw POSIXException(errno, "setrlimit");

    for (int lim = rl.rlim_cur * 2 - 1, bound = rl.rlim_cur; lim >= bound; --lim)
    {
        rl.rlim_cur = lim;
        rc = ::setrlimit(RLIMIT_NOFILE, &rl);
        if (rc == 0)
            return lim;
    }
    throw POSIXException(errno, "setrlimit");
}

const FileSystemService& FileSystemService::get_default()
{
    static const FileSystemService service;
    return service;
}

std::string FileSystemService::temp_name(const std::string& prefix, const std::string& suffix)
{
    return prefix + random_hex_string(16) + suffix;
}

bool FileSystemService::isatty(int fd) noexcept { return ::isatty(fd); }
}
