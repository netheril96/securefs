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

class HookedFuseHighLevelOps final : public DelegateFuseHighLevelOps
{
public:
    HookedFuseHighLevelOps(std::shared_ptr<FuseHighLevelOpsBase> delegate,
                           std::shared_ptr<FuseHook> hook)
        : DelegateFuseHighLevelOps(std::move(delegate)), hook_(std::move(hook))
    {
    }

    int vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vstatfs(path, buf, ctx);
    }

    int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vgetattr(path, st, ctx);
    }

    int vfgetattr(const char* path,
                  fuse_stat* st,
                  fuse_file_info* info,
                  const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vfgetattr(path, st, info, ctx);
    }

    int vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vopendir(path, info, ctx);
    }

    int vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vreleasedir(path, info, ctx);
    }

    int vreaddir(const char* path,
                 void* buf,
                 fuse_fill_dir_t filler,
                 fuse_off_t off,
                 fuse_file_info* info,
                 const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vreaddir(path, buf, filler, off, info, ctx);
    }

    int vcreate(const char* path,
                fuse_mode_t mode,
                fuse_file_info* info,
                const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vcreate(path, mode, info, ctx);
    }

    int vopen(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vopen(path, info, ctx);
    }

    int vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vrelease(path, info, ctx);
    }

    int vread(const char* path,
              char* buf,
              size_t size,
              fuse_off_t offset,
              fuse_file_info* info,
              const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vread(path, buf, size, offset, info, ctx);
    }

    int vwrite(const char* path,
               const char* buf,
               size_t size,
               fuse_off_t offset,
               fuse_file_info* info,
               const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vwrite(path, buf, size, offset, info, ctx);
    }

    int vflush(const char* path, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vflush(path, info, ctx);
    }

    int vftruncate(const char* path,
                   fuse_off_t len,
                   fuse_file_info* info,
                   const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vftruncate(path, len, info, ctx);
    }

    int vunlink(const char* path, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vunlink(path, ctx);
    }

    int vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vmkdir(path, mode, ctx);
    }

    int vrmdir(const char* path, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vrmdir(path, ctx);
    }

    int vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vchmod(path, mode, ctx);
    }

    int vchown(const char* path, fuse_uid_t uid, fuse_gid_t gid, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vchown(path, uid, gid, ctx);
    }

    int vsymlink(const char* to, const char* from, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vsymlink(to, from, ctx);
    }

    int vlink(const char* src, const char* dest, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vlink(src, dest, ctx);
    }

    int vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vreadlink(path, buf, size, ctx);
    }

    int vrename(const char* from, const char* to, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vrename(from, to, ctx);
    }

    int
    vfsync(const char* path, int datasync, fuse_file_info* info, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vfsync(path, datasync, info, ctx);
    }

    int vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vtruncate(path, len, ctx);
    }

    int vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vutimens(path, ts, ctx);
    }

    int vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vlistxattr(path, list, size, ctx);
    }

    int vgetxattr(const char* path,
                  const char* name,
                  char* value,
                  size_t size,
                  uint32_t position,
                  const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vgetxattr(path, name, value, size, position, ctx);
    }

    int vsetxattr(const char* path,
                  const char* name,
                  const char* value,
                  size_t size,
                  int flags,
                  uint32_t position,
                  const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vsetxattr(path, name, value, size, flags, position, ctx);
    }

    int vremovexattr(const char* path, const char* name, const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vremovexattr(path, name, ctx);
    }

    int vgetpath(const char* path,
                 char* buf,
                 size_t size,
                 fuse_file_info* info,
                 const fuse_context* ctx) override
    {
        hook_->notify_activity();
        return DelegateFuseHighLevelOps::vgetpath(path, buf, size, info, ctx);
    }

private:
    std::shared_ptr<FuseHook> hook_;
};

}    // namespace securefs
