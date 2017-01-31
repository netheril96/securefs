#pragma once

#include "myutils.h"
#include "streams.h"

#include <fcntl.h>
#include <functional>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

struct statvfs;
struct timespec;

#ifdef WIN32

#include <fuse_win.h>
#include <io.h>

#define off_t __int64

typedef ptrdiff_t ssize_t;

#define __PRETTY_FUNCTION__ __FUNCTION__

#define O_RDONLY _O_RDONLY
#define O_WRONLY _O_WRONLY
#define O_RDWR _O_RDWR
#define O_APPEND _O_APPEND
#define O_CREAT _O_CREAT
#define O_TRUNC _O_TRUNC
#define O_EXCL _O_EXCL
#define O_TEXT _O_TEXT
#define O_BINARY _O_BINARY
#define O_RAW _O_BINARY
#define O_TEMPORARY _O_TEMPORARY
#define O_NOINHERIT _O_NOINHERIT
#define O_SEQUENTIAL _O_SEQUENTIAL
#define O_RANDOM _O_RANDOM

#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif

inline int open(const char* fn, int flags, int mode) { return ::_open(fn, flags, mode); }
inline int close(int fd) { return ::_close(fd); }
inline int write(int fd, const void* data, int size) { return ::_write(fd, data, size); }

namespace securefs
{
std::string normalize_to_lower_case(const char* input);
}
#else
typedef struct stat FUSE_STAT;

#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#endif    // WIN32

namespace securefs
{

class FileStream : public StreamBase
{
public:
    virtual void fsync() = 0;
    virtual void utimens(const struct timespec ts[2]) = 0;
    virtual void fstat(FUSE_STAT*) = 0;
    virtual void close() noexcept = 0;
    virtual ssize_t listxattr(char*, size_t) { throwVFSException(ENOTSUP); }
    virtual ssize_t getxattr(const char*, void*, size_t) { throwVFSException(ENOTSUP); }
    virtual void setxattr(const char*, void*, size_t, int) { throwVFSException(ENOTSUP); }
    virtual void removexattr(const char*) { throwVFSException(ENOTSUP); }
};

class DirectoryTraverser
{
    DISABLE_COPY_MOVE(DirectoryTraverser)

public:
    DirectoryTraverser() {}
    virtual ~DirectoryTraverser();
    virtual bool next(std::string* name, mode_t* type) = 0;
};

class OSService
{
private:
    class Impl;
    std::unique_ptr<Impl> impl;

private:
    OSService();

public:
    OSService(const std::string& path);
    ~OSService();
    std::shared_ptr<FileStream>
    open_file_stream(const std::string& path, int flags, unsigned mode) const;
    bool remove_file_nothrow(const std::string& path) const noexcept;
    bool remove_directory_nothrow(const std::string& path) const noexcept;
    void remove_file(const std::string& path) const;
    void remove_directory(const std::string& path) const;

    void rename(const std::string& a, const std::string& b) const;
    void lock() const;
    void ensure_directory(const std::string& path, unsigned mode) const;
    void mkdir(const std::string& path, unsigned mode) const;
    void statfs(struct statvfs*) const;

    // Returns false when the path does not exist; throw exceptions on other errors
    // The ENOENT errors are too frequent so the API is redesigned
    bool stat(const std::string& path, FUSE_STAT* stat);
    void chmod(const std::string& path, mode_t mode);
    ssize_t readlink(const std::string& path, char* output, size_t size);
    void symlink(const std::string& to, const std::string& from);

    typedef std::function<void(const std::string&, const std::string&)> recursive_traverse_callback;
    void recursive_traverse(const std::string& dir,
                            const recursive_traverse_callback& callback) const;

    std::unique_ptr<DirectoryTraverser> create_traverser(const std::string& dir) const;

public:
    static uint32_t getuid() noexcept;
    static uint32_t getgid() noexcept;
    static int raise_fd_limit();
    static bool isatty(int fd) noexcept;

    static std::string temp_name(const std::string& prefix, const std::string& suffix);
    static const OSService& get_default();
    static void get_current_time(timespec& out);
};
}
