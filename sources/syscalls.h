#pragma once

#ifndef _WIN32

#include "exceptions.h"
#include "format.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace securefs
{
namespace syscalls
{
    inline int open(const char* name, int flags, mode_t mode)
    {
        int fd = ::open(name, flags, mode);
        if (fd < 0)
            throw UnderlyingOSException(errno,
                                        fmt::format("Opening {} with flags {}", name, flags));
        return fd;
    }

    inline int openat(int dirfd, const char* name, int flags, mode_t mode)
    {
        int fd = ::openat(dirfd, name, flags, mode);
        if (fd < 0)
            throw UnderlyingOSException(
                errno,
                fmt::format("Opening {} (at directory with fd {}) with flags {}", name, fd, flags));
        return fd;
    }

    inline int close(int fd) noexcept    // No one cares about closing errors anyway
    {
        return ::close(fd);
    }

    inline int unlinkat(int dirfd, const char* name, int flags) noexcept
    {
        return ::unlinkat(dirfd, name, flags);
    }
}
}
#endif

namespace securefs
{
namespace syscalls
{
    class FileDescriptorGuard
    {
    private:
        int m_fd;

    public:
        explicit FileDescriptorGuard(int fd) : m_fd(fd) {}
        FileDescriptorGuard(FileDescriptorGuard&& other) noexcept : m_fd(other.m_fd)
        {
            other.m_fd = -1;
        }
        FileDescriptorGuard& operator=(FileDescriptorGuard&& other) noexcept
        {
            std::swap(m_fd, other.m_fd);
            return *this;
        }
        ~FileDescriptorGuard()
        {
            if (m_fd >= 0)
                ::securefs::syscalls::close(m_fd);
        }
        int get() const noexcept { return m_fd; }
        int release() noexcept
        {
            int fd = m_fd;
            m_fd = -1;
            return fd;
        }
        void reset(int fd) noexcept
        {
            if (m_fd >= 0)
                ::securefs::syscalls::close(m_fd);
            m_fd = fd;
        }
    };
}
}