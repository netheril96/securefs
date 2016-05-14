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

#ifdef _WIN32
typedef unsigned mode_t;
typedef long long ssize_t;
#endif

#ifdef _WIN32
#include <fuse_win.h>
#define off_t long long
typedef struct FUSE_STAT real_stat_type;
#else
typedef struct stat real_stat_type;
#endif

namespace securefs
{

class FileStream : public StreamBase
{
public:
    virtual void fsync() = 0;
    virtual void utimens(const struct timespec ts[2]) = 0;
    virtual void fstat(real_stat_type*) = 0;

    virtual ssize_t listxattr(char*, size_t) { throw OSException(ENOTSUP); }

    virtual ssize_t getxattr(const char*, void*, size_t) { throw OSException(ENOTSUP); }

    virtual void setxattr(const char*, void*, size_t, int) { throw OSException(ENOTSUP); }

    virtual void removexattr(const char*) { throw OSException(ENOTSUP); }
};

class FileSystemServiceImpl;

class FileSystemService
{
private:
    typedef FileSystemServiceImpl Impl;
    std::unique_ptr<Impl> impl;

public:
    FileSystemService();
    FileSystemService(const std::string& path);
    ~FileSystemService();
    std::shared_ptr<FileStream> open_file_stream(const std::string& path, int flags, unsigned mode);
    bool remove_file(const std::string& path) noexcept;
    bool remove_directory(const std::string& path) noexcept;
    void rename(const std::string& a, const std::string& b);
    void lock();
    void ensure_directory(const std::string& path, unsigned mode);
    void statfs(struct statvfs*);

public:
    static uint32_t getuid() noexcept;
    static uint32_t getgid() noexcept;
    static bool raise_fd_limit() noexcept;

    static std::string temp_name(const std::string& prefix, const std::string& suffix)
    {
        return prefix + random_hex_string(16) + suffix;
    }
};
}
