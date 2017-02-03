#ifndef WIN32
#define _DARWIN_BETTER_REALPATH 1
#include "exceptions.h"
#include "logger.h"
#include "platform.h"
#include "streams.h"

#include <algorithm>
#include <locale.h>
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
        m_size = st.st_size;
    }

    ~UnixFileStream() { this->close(); }

    void close() noexcept override
    {
        ::close(m_fd);
        m_fd = -1;
    }

    void lock(bool exclusive) override
    {
        int rc = ::flock(m_fd, exclusive ? LOCK_EX : LOCK_SH);
        if (rc < 0)
        {
            throwPOSIXException(errno, "flock");
        }
    }

    void unlock() override
    {
        int rc = ::flock(m_fd, LOCK_UN);
        if (rc < 0)
        {
            throwPOSIXException(errno, "flock");
        }
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

    void utimens(const struct fuse_timespec ts[2]) override
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
    explicit UnixDirectoryTraverser(StringRef path)
    {
        m_dir = ::opendir(path.c_str());
        if (!m_dir)
            throwPOSIXException(errno, "opendir " + path);
    }
    ~UnixDirectoryTraverser() { ::closedir(m_dir); }

    bool next(std::string* name, fuse_mode_t* type) override
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

std::string OSService::norm_path(StringRef path) const
{
#ifdef HAS_AT_FUNCTIONS
    if (m_dir_fd < 0)
        return path.to_string();
#endif
    if (path.size() > 0 && path[0] == '/')
        return path.to_string();
    return m_dir_name + path;
}

OSService::OSService()
{
#ifdef HAS_AT_FUNCTIONS
    m_dir_fd = AT_FDCWD;
#endif
}

OSService::~OSService()
{
#ifdef HAS_AT_FUNCTIONS
    if (m_dir_fd >= 0)
        ::close(m_dir_fd);
#endif
}

OSService::OSService(StringRef path)
{
    char buffer[PATH_MAX + 1] = {0};
    char* rc = ::realpath(path.c_str(), buffer);
    if (!rc)
        throwPOSIXException(errno, "realpath on " + path);
    m_dir_name.reserve(strlen(buffer) + 1);
    m_dir_name.assign(buffer);
    m_dir_name.push_back('/');

#ifdef HAS_AT_FUNCTIONS
    int dir_fd = ::open(path.c_str(), O_RDONLY);
    if (dir_fd < 0)
        throwPOSIXException(errno, "Opening directory " + path);
    m_dir_fd = dir_fd;
#endif
}

std::shared_ptr<FileStream>
OSService::open_file_stream(StringRef path, int flags, unsigned mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int fd = ::openat(m_dir_fd, path.c_str(), flags, mode);
#else
    int fd = ::open(norm_path(path).c_str(), flags, mode);
#endif
    if (fd < 0)
        throwPOSIXException(errno,
                            strprintf("Opening %s with flags %#o", norm_path(path).c_str(), flags));
    return std::make_shared<UnixFileStream>(fd);
}

void OSService::remove_file(StringRef path) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::unlinkat(m_dir_fd, path.c_str(), 0) == 0;
#else
    int rc = ::unlink(norm_path(path).c_str()) == 0;
#endif
    if (rc < 0)
        throwPOSIXException(errno, "unlinking " + norm_path(path));
}

void OSService::remove_directory(StringRef path) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::unlinkat(m_dir_fd, path.c_str(), AT_REMOVEDIR);
#else
    int rc = ::rmdir(norm_path(path).c_str()) == 0;
#endif
    if (rc < 0)
        throwPOSIXException(errno, "removing directory " + norm_path(path));
}

void OSService::lock() const
{
    int rc = ::flock(m_dir_fd, LOCK_NB | LOCK_EX);
    if (rc < 0)
        throwPOSIXException(errno,
                            strprintf("Fail to obtain exclusive lock on %s", m_dir_name.c_str()));
}

void OSService::mkdir(StringRef path, unsigned mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::mkdirat(m_dir_fd, path.c_str(), mode);
#else
    int rc = ::mkdir(norm_path(path).c_str(), mode);
#endif
    if (rc < 0)
        throwPOSIXException(errno,
                            strprintf("Fail to create directory %s", norm_path(path).c_str()));
}

void OSService::symlink(StringRef to, StringRef from) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::symlinkat(to.c_str(), m_dir_fd, from.c_str());
#else
    int rc = ::symlink(to.c_str(), norm_path(from).c_str());
#endif
    if (rc < 0)
        throwPOSIXException(
            errno, strprintf("symlink to=%s and from=%s", to.c_str(), norm_path(from).c_str()));
}

void OSService::link(StringRef source, StringRef dest) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::linkat(m_dir_fd, source.c_str(), m_dir_fd, dest.c_str(), 0);
#else
    int rc = ::link(norm_path(source).c_str(), norm_path(dest).c_str());
#endif
    if (rc < 0)
    {
        throwPOSIXException(errno, strprintf("link src=%s dest=%s", source.c_str(), dest.c_str()));
    }
}

void OSService::statfs(struct fuse_statvfs* fs_info) const
{
    int rc = ::fstatvfs(m_dir_fd, fs_info);
    if (rc < 0)
        throwPOSIXException(errno, "statvfs");
}

void OSService::rename(StringRef a, StringRef b) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::renameat(m_dir_fd, a.c_str(), m_dir_fd, b.c_str());
#else
    int rc = ::rename(norm_path(a).c_str(), norm_path(b).c_str());
#endif
    if (rc < 0)
        throwPOSIXException(
            errno, strprintf("Renaming from %s to %s", norm_path(a).c_str(), norm_path(b).c_str()));
}

bool OSService::stat(StringRef path, struct fuse_stat* stat) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::fstatat(m_dir_fd, path.c_str(), stat, AT_SYMLINK_NOFOLLOW);
#else
    int rc = ::lstat(norm_path(path).c_str(), stat);
#endif
    if (rc < 0)
    {
        if (errno == ENOENT)
            return false;
        throwPOSIXException(errno, strprintf("stating %s", norm_path(path).c_str()));
    }
    return true;
}

void OSService::chmod(StringRef path, fuse_mode_t mode) const
{
#ifdef HAS_AT_FUNCTIONS
    int rc = ::fchmodat(m_dir_fd, path.c_str(), mode, AT_SYMLINK_NOFOLLOW);
#else
    int rc = ::lchmod(norm_path(path).c_str(), mode);
#endif
    if (rc < 0)
        throwPOSIXException(errno,
                            strprintf("chmod %s with mode=0%o", norm_path(path).c_str(), mode));
}

ssize_t OSService::readlink(StringRef path, char* output, size_t size) const
{
#ifdef HAS_AT_FUNCTIONS
    ssize_t rc = ::readlinkat(m_dir_fd, path.c_str(), output, size);
#else
    ssize_t rc = ::readlink(norm_path(path).c_str(), output, size);
#endif
    if (rc < 0)
        throwPOSIXException(
            errno, strprintf("readlink %s with buffer size=%zu", norm_path(path).c_str(), size));
    return rc;
}

void OSService::utimens(StringRef path, const fuse_timespec* ts) const
{
#if defined(HAS_AT_FUNCTIONS) && defined(HAS_FUTIMENS)
    int rc = ::utimensat(m_dir_fd, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    if (rc < 0)
        throwPOSIXException(errno, "utimensat");
#else
    int rc;
    if (!ts)
    {
        rc = ::lutimes(norm_path(path).c_str(), nullptr);
    }
    else
    {
        struct timeval tv[2];
        tv[0].tv_sec = ts[0].tv_sec;
        tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec;
        tv[1].tv_usec = ts[1].tv_nsec / 1000;
        rc = ::lutimes(norm_path(path).c_str(), tv);
    }
    if (rc < 0)
        throwPOSIXException(errno, "lutimes");
#endif
}

std::unique_ptr<DirectoryTraverser> OSService::create_traverser(StringRef dir) const
{
    return securefs::make_unique<UnixDirectoryTraverser>(norm_path(dir));
}

uint32_t OSService::getuid() { return ::getuid(); }
uint32_t OSService::getgid() { return ::getgid(); }

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

void OSService::get_current_time(fuse_timespec& current_time)
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

#ifdef __APPLE__

ssize_t OSService::listxattr(const char* path, char* buf, size_t size) const noexcept
{
    auto rc = ::listxattr(norm_path(path).c_str(), buf, size, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

ssize_t OSService::getxattr(const char* path, const char* name, void* buf, size_t size) const
    noexcept
{
    auto rc = ::getxattr(norm_path(path).c_str(), name, buf, size, 0, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::setxattr(const char* path, const char* name, void* buf, size_t size, int flags) const
    noexcept
{
    auto rc = ::setxattr(norm_path(path).c_str(), name, buf, size, 0, flags | XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::removexattr(const char* path, const char* name) const noexcept
{
    auto rc = ::removexattr(norm_path(path).c_str(), name, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}
#endif
}
#endif
