#pragma once

#include "fuse_high_level_ops_base.h"
#include "object.h"
#include "resettable_timer.h"

#include <memory>

namespace securefs
{
class FuseHook : public Object
{
public:
    virtual void notify_activity() = 0;
};

class NoOpFuseHook final : public FuseHook
{
public:
    void notify_activity() override {}
};

class IdleShutdownHook final : public FuseHook
{
public:
    explicit IdleShutdownHook(absl::Duration timeout);
    void notify_activity() override;

private:
    absl::Duration timeout_;
    ResettableTimer timer_;
};

class MultiFuseHook final : public FuseHook
{
public:
    void add_hook(std::shared_ptr<FuseHook> hook) { hooks_.push_back(std::move(hook)); }
    void notify_activity() override
    {
        for (auto& hook : hooks_)
        {
            hook->notify_activity();
        }
    }

private:
    std::vector<std::shared_ptr<FuseHook>> hooks_;
};

class HookedFuseHighLevelOps final : public FuseHighLevelOpsBase
{
public:
    HookedFuseHighLevelOps(FuseHighLevelOpsBase& delegate, FuseHook& hook)
        : delegate_(delegate), hook_(hook)
    {
    }

    // Delegate other methods directly
    bool allow_sensitive_logging() const override { return delegate_.allow_sensitive_logging(); }
    void initialize(fuse_conn_info* info) override { delegate_.initialize(info); }
    bool has_statfs() const override { return delegate_.has_statfs(); }
    bool has_getattr() const override { return delegate_.has_getattr(); }
    bool has_fgetattr() const override { return delegate_.has_fgetattr(); }
    bool has_opendir() const override { return delegate_.has_opendir(); }
    bool has_releasedir() const override { return delegate_.has_releasedir(); }
    bool has_readdir() const override { return delegate_.has_readdir(); }
    bool has_create() const override { return delegate_.has_create(); }
    bool has_open() const override { return delegate_.has_open(); }
    bool has_release() const override { return delegate_.has_release(); }
    bool has_read() const override { return delegate_.has_read(); }
    bool has_write() const override { return delegate_.has_write(); }
    bool has_flush() const override { return delegate_.has_flush(); }
    bool has_ftruncate() const override { return delegate_.has_ftruncate(); }
    bool has_unlink() const override { return delegate_.has_unlink(); }
    bool has_mkdir() const override { return delegate_.has_mkdir(); }
    bool has_rmdir() const override { return delegate_.has_rmdir(); }
    bool has_chmod() const override { return delegate_.has_chmod(); }
    bool has_chown() const override { return delegate_.has_chown(); }
    bool has_symlink() const override { return delegate_.has_symlink(); }
    bool has_link() const override { return delegate_.has_link(); }
    bool has_readlink() const override { return delegate_.has_readlink(); }
    bool has_rename() const override { return delegate_.has_rename(); }
    bool has_fsync() const override { return delegate_.has_fsync(); }
    bool has_truncate() const override { return delegate_.has_truncate(); }
    bool has_utimens() const override { return delegate_.has_utimens(); }
    bool has_listxattr() const override { return delegate_.has_listxattr(); }
    bool has_getxattr() const override { return delegate_.has_getxattr(); }
    bool has_setxattr() const override { return delegate_.has_setxattr(); }
    bool has_removexattr() const override { return delegate_.has_removexattr(); }
    bool has_getpath() const override { return delegate_.has_getpath(); }

    // Call hook first, then delegate for vXXX methods
    int vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vstatfs(path, buf, ctx);
    }

    int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vgetattr(path, st, ctx);
    }

    int vfgetattr(const char* path,
                  fuse_stat* st,
                  fuse_file_info* info,
                  const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vfgetattr(path, st, info, ctx);
    }

    int vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vopendir(path, info, ctx);
    }

    int vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vreleasedir(path, info, ctx);
    }

    int vreaddir(const char* path,
                 void* buf,
                 fuse_fill_dir_t filler,
                 fuse_off_t off,
                 fuse_file_info* info,
                 const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vreaddir(path, buf, filler, off, info, ctx);
    }

    int vcreate(const char* path,
                fuse_mode_t mode,
                fuse_file_info* info,
                const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vcreate(path, mode, info, ctx);
    }

    int vopen(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vopen(path, info, ctx);
    }

    int vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vrelease(path, info, ctx);
    }

    int vread(const char* path,
              char* buf,
              size_t size,
              fuse_off_t offset,
              fuse_file_info* info,
              const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vread(path, buf, size, offset, info, ctx);
    }

    int vwrite(const char* path,
               const char* buf,
               size_t size,
               fuse_off_t offset,
               fuse_file_info* info,
               const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vwrite(path, buf, size, offset, info, ctx);
    }

    int vflush(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vflush(path, info, ctx);
    }

    int vftruncate(const char* path,
                   fuse_off_t len,
                   fuse_file_info* info,
                   const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vftruncate(path, len, info, ctx);
    }

    int vunlink(const char* path, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vunlink(path, ctx);
    }

    int vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vmkdir(path, mode, ctx);
    }

    int vrmdir(const char* path, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vrmdir(path, ctx);
    }

    int vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vchmod(path, mode, ctx);
    }

    int vchown(const char* path, fuse_uid_t uid, fuse_gid_t gid, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vchown(path, uid, gid, ctx);
    }

    int vsymlink(const char* to, const char* from, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vsymlink(to, from, ctx);
    }

    int vlink(const char* src, const char* dest, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vlink(src, dest, ctx);
    }

    int vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vreadlink(path, buf, size, ctx);
    }

    int vrename(const char* from, const char* to, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vrename(from, to, ctx);
    }

    int
    vfsync(const char* path, int datasync, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vfsync(path, datasync, info, ctx);
    }

    int vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vtruncate(path, len, ctx);
    }

    int vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vutimens(path, ts, ctx);
    }

    int vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vlistxattr(path, list, size, ctx);
    }

    int vgetxattr(const char* path,
                  const char* name,
                  char* value,
                  size_t size,
                  uint32_t position,
                  const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vgetxattr(path, name, value, size, position, ctx);
    }

    int vsetxattr(const char* path,
                  const char* name,
                  const char* value,
                  size_t size,
                  int flags,
                  uint32_t position,
                  const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vsetxattr(path, name, value, size, flags, position, ctx);
    }

    int vremovexattr(const char* path, const char* name, const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vremovexattr(path, name, ctx);
    }

    int vgetpath(const char* path,
                 char* buf,
                 size_t size,
                 fuse_file_info* info,
                 const fuse_context* ctx) override
    {
        hook_.notify_activity();
        return delegate_.vgetpath(path, buf, size, info, ctx);
    }

private:
    FuseHighLevelOpsBase& delegate_;
    FuseHook& hook_;
};

}    // namespace securefs
