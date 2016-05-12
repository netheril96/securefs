#ifndef _WIN32

#include "exceptions.h"
#include "format.h"
#include "platform.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace securefs
{
class UnixFileStream final : public StreamBase
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

    length_type read(void* output, offset_type offset, length_type length) override
    {
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            throw OSException(errno);
        return rc;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            throw OSException(errno);
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
            throw OSException(errno);
        m_size = new_length;
    }

    length_type size() const override { return m_size; }

    bool is_sparse() const noexcept override { return true; }
};

class UnixRootDirectory : public RootDirectory
{
private:
    std::string dir_name;
    int dir_fd;

public:
    explicit UnixRootDirectory(const char* path, bool readonly) : dir_name(path)
    {
        dir_fd = ::open(path, readonly ? O_RDONLY : O_RDWR);
        if (dir_fd < 0)
            throw UnderlyingOSException(errno, fmt::format("Opening directory {}", path));
    }

    std::shared_ptr<StreamBase>
    open_file_stream(const char* path, int flags, unsigned mode) override
    {
        int fd = ::openat(dir_fd, path, flags, mode);
        if (fd < 0)
            throw UnderlyingOSException(
                errno, fmt::format("Opening {}/{} with flags {}", dir_name, path, flags));
        return std::make_shared<UnixFileStream>(fd);
    }

    bool remove_file(const char* path) noexcept override
    {
        return ::unlinkat(dir_fd, path, 0) == 0;
    }

    bool remove_directory(const char* path) noexcept override
    {
        return ::unlinkat(dir_fd, path, AT_REMOVEDIR);
    }

    void lock() override
    {
        int rc = ::flock(dir_fd, LOCK_NB | LOCK_EX);
        if (rc < 0)
            throw UnderlyingOSException(
                errno, fmt::format("Fail to obtain exclusive lock on {}", dir_name));
    }

    void ensure_directory(const char* path, unsigned mode) override
    {
        int rc = ::mkdirat(dir_fd, path, mode);
        if (rc < 0 && errno != EEXIST)
            throw UnderlyingOSException(
                errno, fmt::format("Fail to create directory {}/{}", dir_name, path));
    }
};
}
#endif