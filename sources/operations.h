#pragma once
#define FUSE_USE_VERSION 27

#include "file_table.h"
#include "logger.h"
#include "myutils.h"

#include <fuse.h>

namespace securefs
{
namespace operations
{
    struct FSOptions
    {
        optional<int> version;
        std::shared_ptr<FileSystemService> root;
        optional<key_type> master_key;
        optional<uint32_t> flags;
        optional<unsigned> block_size;
        optional<unsigned> iv_size;
        std::shared_ptr<Logger> logger;
    };

    struct FileSystem
    {
    public:
        FileTable table;
        id_type root_id;
        std::shared_ptr<Logger> logger;
        unsigned block_size;

        explicit FileSystem(const FSOptions& opt);

        ~FileSystem();
    };

    int statfs(const char*, struct statvfs*);

    void* init(struct fuse_conn_info*);

    void destroy(void* ptr);

    int getattr(const char*, struct stat*);

    int opendir(const char*, struct fuse_file_info*);

    int releasedir(const char*, struct fuse_file_info*);

    int readdir(const char*, void*, fuse_fill_dir_t, off_t, struct fuse_file_info*);

    int create(const char*, mode_t, struct fuse_file_info*);

    int open(const char*, struct fuse_file_info*);

    int release(const char*, struct fuse_file_info*);

    int read(const char*, char*, size_t, off_t, struct fuse_file_info*);

    int write(const char*, const char*, size_t, off_t, struct fuse_file_info*);

    int flush(const char*, struct fuse_file_info*);

    int truncate(const char*, off_t);

    int ftruncate(const char*, off_t, struct fuse_file_info*);

    int unlink(const char*);

    int mkdir(const char*, mode_t);

    int rmdir(const char*);

    int chmod(const char*, mode_t);

    int chown(const char* path, uid_t uid, gid_t gid);

    int symlink(const char* to, const char* from);

    int readlink(const char* path, char* buf, size_t size);

    int rename(const char*, const char*);

    int link(const char*, const char*);

    int fsync(const char* path, int isdatasync, struct fuse_file_info* fi);

    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi);

    int utimens(const char* path, const struct timespec ts[2]);

#ifdef __APPLE__
    int listxattr(const char* path, char* list, size_t size);
    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position);

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position);
    int removexattr(const char* path, const char* name);
#endif
}
}
