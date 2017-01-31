#ifndef WIN32
#define _DARWIN_BETTER_REALPATH 1
#include "exceptions.h"
#include "logger.h"
#include "platform.h"
#include "streams.h"

#include <algorithm>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
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
            throwVFSException(EBADF);
        struct stat st;
        int rc = ::fstat(m_fd, &st);
        if (rc < 0)
        {
            ::close(fd);
            throwPOSIXException(errno, "fstat");
        }
        rc = ::flock(fd, LOCK_EX | LOCK_NB);
        if (rc < 0)
        {
            ::close(fd);
            throwPOSIXException(errno, "flock");
        }
        m_size = st.st_size;
    }

    ~UnixFileStream() { this->close(); }

    void close() noexcept override
    {
        ::flock(m_fd, LOCK_UN);
        ::close(m_fd);
        m_fd = -1;
    }

    void fsync() override
    {
        int rc = ::fsync(m_fd);
        if (rc < 0)
            throwPOSIXException(errno, "fsync");
    }

    void fstat(struct stat* out) override
    {
        if (!out)
            throwVFSException(EFAULT);

        if (::fstat(m_fd, out) < 0)
            throwPOSIXException(errno, "fstat");
    }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            throwPOSIXException(errno, "pread");
        return rc;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            throwPOSIXException(errno, "pwrite");
        if (static_cast<length_type>(rc) != length)
            throwVFSException(EIO);
        if (offset + length > m_size)
            m_size = offset + length;
    }

    void flush() override {}

    void resize(length_type new_length) override
    {
        auto rc = ::ftruncate(m_fd, new_length);
        if (rc < 0)
            throwPOSIXException(errno, "truncate");
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
            throwPOSIXException(errno, "utimens");
    }

#ifdef __APPLE__

    void removexattr(const char* name) override
    {
        auto rc = ::fremovexattr(m_fd, name, 0);
        if (rc < 0)
            throwPOSIXException(errno, "fremovexattr");
    }

    ssize_t getxattr(const char* name, void* value, size_t size) override
    {
        ssize_t rc = ::fgetxattr(m_fd, name, value, size, 0, 0);
        if (rc < 0)
            throwPOSIXException(errno, "fgetxattr");
        return rc;
    }

    ssize_t listxattr(char* buffer, size_t size) override
    {
        auto rc = ::flistxattr(m_fd, buffer, size, 0);
        if (rc < 0)
            throwPOSIXException(errno, "flistxattr");
        return rc;
    }

    void setxattr(const char* name, void* value, size_t size, int flags) override
    {
        auto rc = ::fsetxattr(m_fd, name, value, size, 0, flags);
        if (rc < 0)
            throwPOSIXException(errno, "fsetxattr");
    }
#endif
};

class UnixDirectoryTraverser : public DirectoryTraverser
{
private:
    DIR* m_dir;

public:
    explicit UnixDirectoryTraverser(const std::string& path)
    {
        m_dir = ::opendir(path.c_str());
        if (!m_dir)
            throwPOSIXException(errno, "opendir " + path);
    }
    ~UnixDirectoryTraverser() { ::closedir(m_dir); }

    bool next(std::string* name, mode_t* type) override
    {
        while (1)
        {
            errno = 0;
            auto entry = ::readdir(m_dir);
            if (!entry)
            {
                if (errno)
                    throwPOSIXException(errno, "readdir");
                return false;
            }
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            if (type)
            {
                switch (entry->d_type)
                {
                case DT_DIR:
                    *type = S_IFDIR;
                    break;
                case DT_LNK:
                    *type = S_IFLNK;
                    break;
                case DT_REG:
                    *type = S_IFREG;
                    break;
                default:
                    *type = 0;
                    break;
                }
            }
            if (name)
            {
                *name = entry->d_name;
            }
            return true;
        }
    }
};

class OSService::Impl
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
        return dir_name + path;
    }
};

OSService::OSService() : impl(new Impl()) { impl->dir_fd = AT_FDCWD; }

OSService::~OSService()
{
    if (impl->dir_fd >= 0)
        ::close(impl->dir_fd);
}

OSService::OSService(const std::string& path) : impl(new Impl())
{
    char buffer[PATH_MAX + 1] = {0};
    char* rc = ::realpath(path.c_str(), buffer);
    if (!rc)
        throwPOSIXException(errno, "realpath on " + path);
    impl->dir_name.reserve(strlen(buffer) + 1);
    impl->dir_name.assign(buffer);
    impl->dir_name.push_back('/');

    int dir_fd = ::open(path.c_str(), O_RDONLY);
    if (dir_fd < 0)
        throwPOSIXException(errno, "Opening directory " + path);
    impl->dir_fd = dir_fd;
}

std::shared_ptr<FileStream>
OSService::open_file_stream(const std::string& path, int flags, unsigned mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int fd = ::openat(impl->dir_fd, path.c_str(), flags, mode);
#else
    int fd = ::open(impl->norm_path(path).c_str(), flags, mode);
#endif
    if (fd < 0)
        throwPOSIXException(
            errno, strprintf("Opening %s with flags %#o", impl->norm_path(path).c_str(), flags));
    return std::make_shared<UnixFileStream>(fd);
}

void OSService::remove_file(const std::string& path) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::unlinkat(impl->dir_fd, path.c_str(), 0) == 0;
#else
    int rc = ::unlink(impl->norm_path(path).c_str()) == 0;
#endif
    if (rc < 0)
        throwPOSIXException(errno, "unlinking " + impl->norm_path(path));
}

void OSService::remove_directory(const std::string& path) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::unlinkat(impl->dir_fd, path.c_str(), AT_REMOVEDIR);
#else
    int rc = ::rmdir(impl->norm_path(path).c_str()) == 0;
#endif
    if (rc < 0)
        throwPOSIXException(errno, "removing directory " + impl->norm_path(path));
}

void OSService::lock() const
{
    int rc = ::flock(impl->dir_fd, LOCK_NB | LOCK_EX);
    if (rc < 0)
        throwPOSIXException(
            errno, strprintf("Fail to obtain exclusive lock on %s", impl->dir_name.c_str()));
}

void OSService::mkdir(const std::string& path, unsigned mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::mkdirat(impl->dir_fd, path.c_str(), mode);
#else
    int rc = ::mkdir(impl->norm_path(path).c_str(), mode);
#endif
    if (rc < 0)
        throwPOSIXException(
            errno, strprintf("Fail to create directory %s", impl->norm_path(path).c_str()));
}

void OSService::symlink(const std::string& to, const std::string& from)
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::symlinkat(to.c_str(), impl->dir_fd, from.c_str());
#else
    int rc = ::symlink(to.c_str(), impl->norm_path(from).c_str());
#endif
    if (rc < 0)
        throwPOSIXException(
            errno,
            strprintf("symlink to=%s and from=%s", to.c_str(), impl->norm_path(from).c_str()));
}
void OSService::statfs(struct statvfs* fs_info) const
{
    int rc = ::fstatvfs(impl->dir_fd, fs_info);
    if (rc < 0)
        throwPOSIXException(errno, "statvfs");
}

void OSService::rename(const std::string& a, const std::string& b) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::renameat(impl->dir_fd, a.c_str(), impl->dir_fd, b.c_str());
#else
    int rc = ::rename(impl->norm_path(a).c_str(), impl->norm_path(b).c_str());
#endif
    if (rc < 0)
        throwPOSIXException(errno,
                            strprintf("Renaming from %s to %s",
                                      impl->norm_path(a).c_str(),
                                      impl->norm_path(b).c_str()));
}

bool OSService::stat(const std::string& path, FUSE_STAT* stat)
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::fstatat(impl->dir_fd, path.c_str(), stat, AT_SYMLINK_NOFOLLOW);
#else
    int rc = ::lstat(impl->norm_path(path).c_str(), stat);
#endif
    if (rc < 0)
    {
        if (errno == ENOENT)
            return false;
        throwPOSIXException(errno, strprintf("stating %s", impl->norm_path(path).c_str()));
    }
    return true;
}

void OSService::chmod(const std::string& path, mode_t mode)
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::fchmodat(impl->dir_fd, path.c_str(), mode, AT_SYMLINK_NOFOLLOW);
#else
    int rc = ::lchmod(impl->norm_path(path).c_str(), mode);
#endif
    if (rc < 0)
        throwPOSIXException(
            errno, strprintf("chmod %s with mode=0%o", impl->norm_path(path).c_str(), mode));
}

ssize_t OSService::readlink(const std::string& path, char* output, size_t size)
{
#ifdef HAS_AT_FUNCTIONS
    ssize_t rc = ::readlinkat(impl->dir_fd, path.c_str(), output, size);
#else
    ssize_t rc = ::readlink(impl->norm_path(path).c_str(), output, size);
#endif
    if (rc < 0)
        throwPOSIXException(
            errno,
            strprintf("readlink %s with buffer size=%zu", impl->norm_path(path).c_str(), size));
    return rc;
}

void OSService::utimens(const std::string& path, const timespec* ts) const
{
#if defined(HAS_AT_FUNCTIONS) && defined(HAS_FUTIMENS)
    int rc = ::utimensat(impl->dir_fd, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    if (rc < 0)
        throwPOSIXException(errno, "utimensat");
#else
    int rc;
    if (!ts)
    {
        rc = ::lutimes(impl->norm_path(path).c_str(), nullptr);
    }
    else
    {
        struct timeval tv[2];
        tv[0].tv_sec = ts[0].tv_sec;
        tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec;
        tv[1].tv_usec = ts[1].tv_nsec / 1000;
        rc = ::lutimes(impl->norm_path(path).c_str(), tv);
    }
    if (rc < 0)
        throwPOSIXException(errno, "lutimes");
#endif
}

std::unique_ptr<DirectoryTraverser> OSService::create_traverser(const std::string& dir) const
{
    return securefs::make_unique<UnixDirectoryTraverser>(impl->norm_path(dir));
}

uint32_t OSService::getuid() noexcept { return ::getuid(); }
uint32_t OSService::getgid() noexcept { return ::getgid(); }

int OSService::raise_fd_limit()
{
    struct rlimit rl;
    int rc = ::getrlimit(RLIMIT_NOFILE, &rl);
    if (rc < 0)
        throwPOSIXException(errno, "getrlimit");

    rl.rlim_cur = 10240 * 16;
    do
    {
        rl.rlim_cur /= 2;
        rc = ::setrlimit(RLIMIT_NOFILE, &rl);
    } while (rc < 0 && rl.rlim_cur >= 1024);

    if (rc < 0)
        throwPOSIXException(errno, "setrlimit");

    for (auto lim = rl.rlim_cur * 2 - 1, bound = rl.rlim_cur; lim >= bound; --lim)
    {
        rl.rlim_cur = lim;
        rc = ::setrlimit(RLIMIT_NOFILE, &rl);
        if (rc == 0)
            return static_cast<int>(lim);
    }
    throwPOSIXException(errno, "setrlimit");
}

bool OSService::isatty(int fd) noexcept { return ::isatty(fd) != 0; }

void OSService::get_current_time(timespec& current_time)
{
#ifdef HAS_CLOCK_GETTIME
    clock_gettime(CLOCK_REALTIME, &current_time);
#else
    timeval tv;
    gettimeofday(&tv, nullptr);
    current_time.tv_sec = tv.tv_sec;
    current_time.tv_nsec = tv.tv_usec * 1000;
#endif
}

std::string WindowsException::message() const
{
    return strprintf("Win32 error %ld (%s)", m_err, m_msg.c_str());
}

int WindowsException::error_number() const noexcept { return EPERM; }

#ifdef __APPLE__

ssize_t OSService::listxattr(const char* path, char* buf, size_t size) const noexcept
{
    auto rc = ::listxattr(impl->norm_path(path).c_str(), buf, size, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

ssize_t OSService::getxattr(const char* path, const char* name, void* buf, size_t size) const
    noexcept
{
    auto rc = ::getxattr(impl->norm_path(path).c_str(), name, buf, size, 0, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::setxattr(const char* path, const char* name, void* buf, size_t size, int flags) const
    noexcept
{
    auto rc = ::setxattr(impl->norm_path(path).c_str(), name, buf, size, 0, flags | XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::removexattr(const char* path, const char* name) const noexcept
{
    auto rc = ::removexattr(impl->norm_path(path).c_str(), name, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}
#endif
}
#endif
