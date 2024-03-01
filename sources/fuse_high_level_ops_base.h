#pragma once

#include "myutils.h"
#include "platform.h"

namespace securefs
{
class FuseHighLevelOpsBase
{
public:
    FuseHighLevelOpsBase() = default;
    virtual ~FuseHighLevelOpsBase() = default;
    DISABLE_COPY_MOVE(FuseHighLevelOpsBase)
    static fuse_operations build_ops();

    virtual int vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx) = 0;
    virtual int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) = 0;
    virtual int
    vfgetattr(const char* path, fuse_stat* st, fuse_file_info* info, const fuse_context* ctx)
        = 0;
    virtual int vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;
    virtual int vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;
    virtual int vreaddir(const char* path,
                         void* buf,
                         fuse_fill_dir_t filler,
                         fuse_off_t off,
                         fuse_file_info* info,
                         const fuse_context* ctx)
        = 0;
    virtual int
    vcreate(const char* path, fuse_mode_t mode, fuse_file_info* info, const fuse_context* ctx)
        = 0;
    virtual int vopen(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;
    virtual int vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;
    virtual int vread(const char* path,
                      char* buf,
                      size_t size,
                      fuse_off_t offset,
                      fuse_file_info* info,
                      const fuse_context* ctx)
        = 0;
    virtual int vwrite(const char* path,
                       const char* buf,
                       size_t size,
                       fuse_off_t offset,
                       fuse_file_info* info,
                       const fuse_context* ctx)
        = 0;
    virtual int vflush(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;
    virtual int
    vftruncate(const char* path, fuse_off_t len, fuse_file_info* info, const fuse_context* ctx)
        = 0;
    virtual int vunlink(const char* path, const fuse_context* ctx) = 0;
    virtual int vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx) = 0;
    virtual int vrmdir(const char* path, const fuse_context* ctx) = 0;
    virtual int vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx) = 0;
    virtual int vchown(const char* path, fuse_uid_t uid, fuse_gid_t gid, const fuse_context* ctx)
        = 0;
    virtual int vsymlink(const char* to, const char* from, const fuse_context* ctx) = 0;
    virtual int vlink(const char* src, const char* dest, const fuse_context* ctx) = 0;
    virtual int vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx) = 0;
    virtual int vrename(const char* from, const char* to, const fuse_context* ctx) = 0;
    virtual int
    vfsync(const char* path, int datasync, fuse_file_info* info, const fuse_context* ctx)
        = 0;
    virtual int vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx) = 0;
    virtual int vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx) = 0;
    virtual int vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx) = 0;
    virtual int vgetxattr(const char* path,
                          const char* name,
                          char* value,
                          size_t size,
                          uint32_t position,
                          const fuse_context* ctx)
        = 0;
    virtual int vsetxattr(const char* path,
                          const char* name,
                          const char* value,
                          size_t size,
                          int flags,
                          uint32_t position,
                          const fuse_context* ctx)
        = 0;
    virtual int vremovexattr(const char* path, const char* name, const fuse_context* ctx) = 0;

private:
    static int static_statfs(const char* path, fuse_statvfs* buf);
    static int static_getattr(const char* path, fuse_stat* st);
    static int static_fgetattr(const char* path, fuse_stat* st, fuse_file_info* info);
    static int static_opendir(const char* path, fuse_file_info* info);
    static int static_releasedir(const char* path, fuse_file_info* info);
    static int static_readdir(
        const char* path, void* buf, fuse_fill_dir_t filler, fuse_off_t off, fuse_file_info* info);
    static int static_create(const char* path, fuse_mode_t mode, fuse_file_info* info);
    static int static_open(const char* path, fuse_file_info* info);
    static int static_release(const char* path, fuse_file_info* info);
    static int
    static_read(const char* path, char* buf, size_t size, fuse_off_t offset, fuse_file_info* info);
    static int static_write(
        const char* path, const char* buf, size_t size, fuse_off_t offset, fuse_file_info* info);
    static int static_flush(const char* path, fuse_file_info* info);
    static int static_ftruncate(const char* path, fuse_off_t len, fuse_file_info* info);
    static int static_unlink(const char* path);
    static int static_mkdir(const char* path, fuse_mode_t mode);
    static int static_rmdir(const char* path);
    static int static_chmod(const char* path, fuse_mode_t mode);
    static int static_chown(const char* path, fuse_uid_t uid, fuse_gid_t gid);
    static int static_symlink(const char* to, const char* from);
    static int static_link(const char* src, const char* dest);
    static int static_readlink(const char* path, char* buf, size_t size);
    static int static_rename(const char* from, const char* to);
    static int static_fsync(const char* path, int datasync, fuse_file_info* info);
    static int static_truncate(const char* path, fuse_off_t len);
    static int static_utimens(const char* path, const fuse_timespec* ts);
    static int static_listxattr(const char* path, char* list, size_t size);
    static int static_getxattr(
        const char* path, const char* name, char* value, size_t size, uint32_t position);
    static int static_setxattr(const char* path,
                               const char* name,
                               const char* value,
                               size_t size,
                               int flags,
                               uint32_t position);
    static int static_removexattr(const char* path, const char* name);
};
}    // namespace securefs
