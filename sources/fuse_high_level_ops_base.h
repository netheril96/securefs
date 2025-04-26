#pragma once

#include "object.h"
#include "platform.h"    // IWYU pragma: keep

#include <optional>

namespace securefs
{
struct OwnerOverride
{
    std::optional<int> uid_override, gid_override;
};

class FuseHighLevelOpsBase : public Object
{
public:
    static fuse_operations build_ops(const FuseHighLevelOpsBase* op);

    virtual void initialize(fuse_conn_info* info) = 0;

    virtual bool has_statfs() const { return true; }
    virtual int vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx) = 0;

    virtual bool has_getattr() const { return true; }
    virtual int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) = 0;

    virtual bool has_fgetattr() const { return true; }
    virtual int
    vfgetattr(const char* path, fuse_stat* st, fuse_file_info* info, const fuse_context* ctx)
        = 0;

    virtual bool has_opendir() const { return true; }
    virtual int vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;

    virtual bool has_releasedir() const { return true; }
    virtual int vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;

    virtual bool has_readdir() const { return true; }
    virtual int vreaddir(const char* path,
                         void* buf,
                         fuse_fill_dir_t filler,
                         fuse_off_t off,
                         fuse_file_info* info,
                         const fuse_context* ctx)
        = 0;

    virtual bool has_create() const { return true; }
    virtual int
    vcreate(const char* path, fuse_mode_t mode, fuse_file_info* info, const fuse_context* ctx)
        = 0;

    virtual bool has_open() const { return true; }
    virtual int vopen(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;

    virtual bool has_release() const { return true; }
    virtual int vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;

    virtual bool has_read() const { return true; }
    virtual int vread(const char* path,
                      char* buf,
                      size_t size,
                      fuse_off_t offset,
                      fuse_file_info* info,
                      const fuse_context* ctx)
        = 0;

    virtual bool has_write() const { return true; }
    virtual int vwrite(const char* path,
                       const char* buf,
                       size_t size,
                       fuse_off_t offset,
                       fuse_file_info* info,
                       const fuse_context* ctx)
        = 0;

    virtual bool has_flush() const { return true; }
    virtual int vflush(const char* path, fuse_file_info* info, const fuse_context* ctx) = 0;

    virtual bool has_ftruncate() const { return true; }
    virtual int
    vftruncate(const char* path, fuse_off_t len, fuse_file_info* info, const fuse_context* ctx)
        = 0;

    virtual bool has_unlink() const { return true; }
    virtual int vunlink(const char* path, const fuse_context* ctx) = 0;

    virtual bool has_mkdir() const { return true; }
    virtual int vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx) = 0;

    virtual bool has_rmdir() const { return true; }
    virtual int vrmdir(const char* path, const fuse_context* ctx) = 0;

    virtual bool has_chmod() const { return true; }
    virtual int vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx) = 0;

    virtual bool has_chown() const { return true; }
    virtual int vchown(const char* path, fuse_uid_t uid, fuse_gid_t gid, const fuse_context* ctx)
        = 0;

    virtual bool has_symlink() const { return true; }
    virtual int vsymlink(const char* to, const char* from, const fuse_context* ctx) = 0;

    virtual bool has_link() const { return true; }
    virtual int vlink(const char* src, const char* dest, const fuse_context* ctx) = 0;

    virtual bool has_readlink() const { return true; }
    virtual int vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx) = 0;

    virtual bool has_rename() const { return true; }
    virtual int vrename(const char* from, const char* to, const fuse_context* ctx) = 0;

    virtual bool has_fsync() const { return true; }
    virtual int
    vfsync(const char* path, int datasync, fuse_file_info* info, const fuse_context* ctx)
        = 0;

    virtual bool has_truncate() const { return true; }
    virtual int vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx) = 0;

    virtual bool has_utimens() const { return true; }
    virtual int vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx) = 0;

    virtual bool has_listxattr() const { return true; }
    virtual int vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx) = 0;

    virtual bool has_getxattr() const { return true; }
    virtual int vgetxattr(const char* path,
                          const char* name,
                          char* value,
                          size_t size,
                          uint32_t position,
                          const fuse_context* ctx)
        = 0;

    virtual bool has_setxattr() const { return true; }
    virtual int vsetxattr(const char* path,
                          const char* name,
                          const char* value,
                          size_t size,
                          int flags,
                          uint32_t position,
                          const fuse_context* ctx)
        = 0;

    virtual bool has_removexattr() const { return true; }
    virtual int vremovexattr(const char* path, const char* name, const fuse_context* ctx) = 0;

    virtual bool has_getpath() const { return false; }
    virtual int vgetpath(
        const char* path, char* buf, size_t size, fuse_file_info* info, const fuse_context* ctx)
    {
        return -ENOSYS;
    }

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
    static int static_getxattr(const char* path, const char* name, char* value, size_t size)
    {
        return static_getxattr(path, name, value, size, 0);
    }
    static int static_setxattr(const char* path,
                               const char* name,
                               const char* value,
                               size_t size,
                               int flags,
                               uint32_t position);
    static int
    static_setxattr(const char* path, const char* name, const char* value, size_t size, int flags)
    {
        return static_setxattr(path, name, value, size, flags, 0);
    }
    static int static_removexattr(const char* path, const char* name);
    static int static_getpath(const char* path, char* buf, size_t size, fuse_file_info* info);
    static int static_ioctl(const char* path,
                            int cmd,
                            void* arg,
                            struct fuse_file_info* fi,
                            unsigned int flags,
                            void* data);
};
}    // namespace securefs
