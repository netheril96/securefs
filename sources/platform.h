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

#include <fuse.h>

#ifdef WIN32
#include <io.h>

typedef ptrdiff_t ssize_t;

#define __PRETTY_FUNCTION__ __FUNCTION__

#define O_RDONLY 0x0000   /* open for reading only */
#define O_WRONLY 0x0001   /* open for writing only */
#define O_RDWR 0x0002     /* open for reading and writing */
#define O_ACCMODE 0x0003  /* mask for above modes */
#define O_NONBLOCK 0x0004 /* no delay */
#define O_APPEND 0x0008   /* set append mode */
#define O_SHLOCK 0x0010   /* open with shared file lock */
#define O_EXLOCK 0x0020   /* open with exclusive file lock */
#define O_ASYNC 0x0040    /* signal pgrp when data ready */
#define O_FSYNC O_SYNC    /* source compatibility: do not use */
#define O_NOFOLLOW 0x0100 /* don't follow symlinks */
#define O_CREAT 0x0200    /* create if nonexistant */
#define O_TRUNC 0x0400    /* truncate to zero length */
#define O_EXCL 0x0800     /* error if already exists */
#define S_IFMT 0170000    /* type of file */
#define S_IFIFO 0010000   /* named pipe (fifo) */
#define S_IFCHR 0020000   /* character special */
#define S_IFDIR 0040000   /* directory */
#define S_IFBLK 0060000   /* block special */
#define S_IFREG 0100000   /* regular */
#define S_IFLNK 0120000   /* symbolic link */
#define S_IFSOCK 0140000  /* socket */

#else
#define fuse_uid_t uid_t
#define fuse_gid_t gid_t
#define fuse_pid_t pid_t

#define fuse_dev_t dev_t
#define fuse_ino_t ino_t
#define fuse_mode_t mode_t
#define fuse_nlink_t nlink_t
#define fuse_off_t off_t

#define fuse_fsblkcnt_t fsblkcnt_t
#define fuse_fsfilcnt_t fsfilcnt_t
#define fuse_blksize_t blksize_t
#define fuse_blkcnt_t blkcnt_t

#define fuse_utimbuf utimbuf
#define fuse_timespec timespec

#define fuse_stat stat
#define fuse_statvfs statvfs
#define fuse_flock flock
#endif    // WIN32

namespace securefs
{

class FileStream : public StreamBase
{
public:
    virtual void fsync() = 0;
    virtual void utimens(const struct fuse_timespec ts[2]) = 0;
    virtual void fstat(struct fuse_stat*) = 0;
    virtual void close() noexcept = 0;
    virtual ssize_t listxattr(char*, size_t) { throwVFSException(ENOTSUP); }
    virtual ssize_t getxattr(const char*, void*, size_t) { throwVFSException(ENOTSUP); }
    virtual void setxattr(const char*, void*, size_t, int) { throwVFSException(ENOTSUP); }
    virtual void removexattr(const char*) { throwVFSException(ENOTSUP); }
    virtual void lock(bool exclusive) = 0;
    virtual void unlock() = 0;
};

class DirectoryTraverser
{
    DISABLE_COPY_MOVE(DirectoryTraverser)

public:
    DirectoryTraverser() {}
    virtual ~DirectoryTraverser();
    virtual bool next(std::string* name, fuse_mode_t* type) = 0;
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
#elif defined(WIN32)
    void* m_root_handle;
#endif
    std::string m_dir_name;

public:
    native_string_type norm_path(StringRef path) const;

public:
    OSService();
    explicit OSService(StringRef path);
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
    void statfs(struct fuse_statvfs*) const;
    void utimens(StringRef path, const fuse_timespec ts[2]) const;

    // Returns false when the path does not exist; throw exceptions on other errors
    // The ENOENT errors are too frequent so the API is redesigned
    bool stat(StringRef path, struct fuse_stat* stat) const;

    void link(StringRef source, StringRef dest) const;
    void chmod(StringRef path, fuse_mode_t mode) const;
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
    static uint32_t getuid();
    static uint32_t getgid();
    static int raise_fd_limit();

    static std::string temp_name(StringRef prefix, StringRef suffix);
    static const OSService& get_default();
    static void get_current_time(fuse_timespec& out);
    static void read_password_no_confirmation(const char* prompt,
                                              CryptoPP::AlignedSecByteBlock* output);
    static void read_password_with_confirmation(const char* prompt,
                                                CryptoPP::AlignedSecByteBlock* output);
};
}
