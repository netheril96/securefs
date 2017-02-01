#pragma once

#include "mystring.h"
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
    virtual void lock() = 0;
    virtual void unlock() = 0;
};

class DirectoryTraverser
{
    DISABLE_COPY_MOVE(DirectoryTraverser)

public:
    DirectoryTraverser() {}
    virtual ~DirectoryTraverser();
    virtual bool next(std::string* name, mode_t* type) = 0;
};

#ifdef WIN32
typedef std::wstring native_string_type;
#else
typedef std::string native_string_type;
#endif

class OSService
{
private:
#ifdef HAS_AT_FUNCTIONS
    int m_dir_fd;
#endif
    native_string_type m_dir_name;

    native_string_type norm_path(StringRef path) const;

public:
    OSService();
    OSService(StringRef path);
    ~OSService();
    std::shared_ptr<FileStream> open_file_stream(StringRef path, int flags, unsigned mode) const;
    bool remove_file_nothrow(StringRef path) const noexcept;
    bool remove_directory_nothrow(StringRef path) const noexcept;
    void remove_file(StringRef path) const;
    void remove_directory(StringRef path) const;

    void rename(StringRef a, StringRef b) const;
    void lock() const;
    void ensure_directory(StringRef path, unsigned mode) const;
    void mkdir(StringRef path, unsigned mode) const;
    void statfs(struct statvfs*) const;
    void utimens(StringRef path, const timespec ts[2]) const;

    // Returns false when the path does not exist; throw exceptions on other errors
    // The ENOENT errors are too frequent so the API is redesigned
    bool stat(StringRef path, FUSE_STAT* stat) const;

    void link(StringRef source, StringRef dest) const;
    void chmod(StringRef path, mode_t mode) const;
    ssize_t readlink(StringRef path, char* output, size_t size) const;
    void symlink(StringRef source, StringRef dest) const;

    typedef std::function<void(StringRef, StringRef)> recursive_traverse_callback;
    void recursive_traverse(StringRef dir, const recursive_traverse_callback& callback) const;

    std::unique_ptr<DirectoryTraverser> create_traverser(StringRef dir) const;

#ifdef __APPLE__
    // These APIs, unlike all others, report errors through negative error numbers as defined in
    // <errno.h>
    ssize_t listxattr(const char* path, char* buf, size_t size) const noexcept;
    ssize_t getxattr(const char* path, const char* name, void* buf, size_t size) const noexcept;
    int setxattr(const char* path, const char* name, void* buf, size_t size, int flags) const
        noexcept;
    int removexattr(const char* path, const char* name) const noexcept;
#endif
public:
    static uint32_t getuid() noexcept;
    static uint32_t getgid() noexcept;
    static int raise_fd_limit();
    static bool isatty(int fd) noexcept;

    static std::string temp_name(StringRef prefix, StringRef suffix);
    static const OSService& get_default();
    static void get_current_time(timespec& out);
};
}
