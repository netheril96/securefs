#pragma once

#include "myutils.h"
#include "streams.h"

#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct statvfs;
struct timespec;

namespace securefs
{

class FileStream : public StreamBase
{
public:
    virtual void fsync() = 0;
    virtual void utimens(const struct timespec ts[2]) = 0;
    virtual void fstat(struct stat*) = 0;

    virtual ssize_t listxattr(char*, size_t) { throw OSException(ENOTSUP); }

    virtual ssize_t getxattr(const char*, void*, size_t) { throw OSException(ENOTSUP); }

    virtual void setxattr(const char*, void*, size_t, int) { throw OSException(ENOTSUP); }

    virtual void removexattr(const char*) { throw OSException(ENOTSUP); }
};

class FileSystemService
{
private:
    class Impl;
    std::unique_ptr<Impl> impl;

private:
    FileSystemService();

public:
    FileSystemService(const std::string& path);
    ~FileSystemService();
    std::shared_ptr<FileStream>
    open_file_stream(const std::string& path, int flags, unsigned mode) const;
    bool remove_file(const std::string& path) const noexcept;
    bool remove_directory(const std::string& path) const noexcept;
    void rename(const std::string& a, const std::string& b) const;
    void lock() const;
    void ensure_directory(const std::string& path, unsigned mode) const;
    void statfs(struct statvfs*) const;

public:
    static uint32_t getuid() noexcept;
    static uint32_t getgid() noexcept;
    static int raise_fd_limit();

    static std::string temp_name(const std::string& prefix, const std::string& suffix);
    static const FileSystemService& get_default();
};
}
