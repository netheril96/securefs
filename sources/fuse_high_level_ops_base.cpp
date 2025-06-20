#include "fuse_high_level_ops_base.h"
#include "exceptions.h"
#include "fuse2_workaround.h"
#include "fuse_tracer_v2.h"
#include "is_fuse_t.h"
#include "logger.h"
#include "platform.h"

#include <absl/functional/function_ref.h>
#include <cerrno>
#include <memory>

#if __has_include(<sys/ioctl.h>)
#include <sys/ioctl.h>
#endif

namespace securefs
{
int FuseHighLevelOpsBase::static_statfs(const char* path, fuse_statvfs* buf)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vstatfs(path, buf, ctx); },
                                          "statfs",
                                          __LINE__,
                                          {{"path", {path}}, {"buf", {buf}}});
}
int FuseHighLevelOpsBase::static_getattr(const char* path, fuse_stat* st)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vgetattr(path, st, ctx); },
                                          "getattr",
                                          __LINE__,
                                          {{"path", {path}}, {"st", {st}}});
}
int FuseHighLevelOpsBase::static_fgetattr(const char* path, fuse_stat* st, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vfgetattr(path, st, info, ctx); },
                                          "fgetattr",
                                          __LINE__,
                                          {{"path", {path}}, {"st", {st}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_opendir(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vopendir(path, info, ctx); },
                                          "opendir",
                                          __LINE__,
                                          {{"path", {path}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_releasedir(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vreleasedir(path, info, ctx); },
                                          "releasedir",
                                          __LINE__,
                                          {{"path", {path}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_readdir(
    const char* path, void* buf, fuse_fill_dir_t filler, fuse_off_t off, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vreaddir(path, buf, filler, off, info, ctx); },
        "readdir",
        __LINE__,
        {{"path", {path}}, {"buf", {buf}}, {"filler", {filler}}, {"off", {off}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_create(const char* path, fuse_mode_t mode, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vcreate(path, mode, info, ctx); },
                                          "create",
                                          __LINE__,
                                          {{"path", {path}}, {"mode", {mode}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_open(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vopen(path, info, ctx); },
                                          "open",
                                          __LINE__,
                                          {{"path", {path}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_release(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vrelease(path, info, ctx); },
                                          "release",
                                          __LINE__,
                                          {{"path", {path}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_read(
    const char* path, char* buf, size_t size, fuse_off_t offset, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vread(path, buf, size, offset, info, ctx); },
        "read",
        __LINE__,
        {{"path", {path}},
         op->allow_sensitive_logging()
             ? trace::WrappedFuseArg{"buf", trace::PlainRawBuffer{buf, size}}
             : trace::WrappedFuseArg{"buf", trace::RedactedRawBuffer{buf, size}},
         {"size", {size}},
         {"offset", {offset}},
         {"info", {info}}});
}
int FuseHighLevelOpsBase::static_write(
    const char* path, const char* buf, size_t size, fuse_off_t offset, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vwrite(path, buf, size, offset, info, ctx); },
        "write",
        __LINE__,
        {{"path", {path}},
         op->allow_sensitive_logging()
             ? trace::WrappedFuseArg{"buf", trace::PlainRawBuffer{buf, size}}
             : trace::WrappedFuseArg{"buf", trace::RedactedRawBuffer{buf, size}},
         {"size", {size}},
         {"offset", {offset}},
         {"info", {info}}});
}
int FuseHighLevelOpsBase::static_flush(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vflush(path, info, ctx); },
                                          "flush",
                                          __LINE__,
                                          {{"path", {path}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_ftruncate(const char* path, fuse_off_t len, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vftruncate(path, len, info, ctx); },
                                          "ftruncate",
                                          __LINE__,
                                          {{"path", {path}}, {"len", {len}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_unlink(const char* path)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vunlink(path, ctx); }, "unlink", __LINE__, {{"path", {path}}});
}
int FuseHighLevelOpsBase::static_mkdir(const char* path, fuse_mode_t mode)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vmkdir(path, mode, ctx); },
                                          "mkdir",
                                          __LINE__,
                                          {{"path", {path}}, {"mode", {mode}}});
}
int FuseHighLevelOpsBase::static_rmdir(const char* path)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vrmdir(path, ctx); }, "rmdir", __LINE__, {{"path", {path}}});
}
int FuseHighLevelOpsBase::static_chmod(const char* path, fuse_mode_t mode)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vchmod(path, mode, ctx); },
                                          "chmod",
                                          __LINE__,
                                          {{"path", {path}}, {"mode", {mode}}});
}
int FuseHighLevelOpsBase::static_chown(const char* path, fuse_uid_t uid, fuse_gid_t gid)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vchown(path, uid, gid, ctx); },
                                          "chown",
                                          __LINE__,
                                          {{"path", {path}}, {"uid", {uid}}, {"gid", {gid}}});
}
int FuseHighLevelOpsBase::static_symlink(const char* to, const char* from)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vsymlink(to, from, ctx); },
                                          "symlink",
                                          __LINE__,
                                          {{"to", {to}}, {"from", {from}}});
}
int FuseHighLevelOpsBase::static_link(const char* src, const char* dest)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vlink(src, dest, ctx); },
                                          "link",
                                          __LINE__,
                                          {{"src", {src}}, {"dest", {dest}}});
}
int FuseHighLevelOpsBase::static_readlink(const char* path, char* buf, size_t size)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vreadlink(path, buf, size, ctx); },
        "readlink",
        __LINE__,
        {{"path", {path}},
         trace::WrappedFuseArg{"buf", trace::RedactedRawBuffer{buf, size}},
         {"size", {size}}});
}
int FuseHighLevelOpsBase::static_rename(const char* from, const char* to)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vrename(from, to, ctx); },
                                          "rename",
                                          __LINE__,
                                          {{"from", {from}}, {"to", {to}}});
}
int FuseHighLevelOpsBase::static_fsync(const char* path, int datasync, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vfsync(path, datasync, info, ctx); },
        "fsync",
        __LINE__,
        {{"path", {path}}, {"datasync", {datasync}}, {"info", {info}}});
}
int FuseHighLevelOpsBase::static_truncate(const char* path, fuse_off_t len)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vtruncate(path, len, ctx); },
                                          "truncate",
                                          __LINE__,
                                          {{"path", {path}}, {"len", {len}}});
}
int FuseHighLevelOpsBase::static_utimens(const char* path, const fuse_timespec* ts)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vutimens(path, ts, ctx); },
                                          "utimens",
                                          __LINE__,
                                          {{"path", {path}}, {"ts", {ts}}});
}
int FuseHighLevelOpsBase::static_listxattr(const char* path, char* list, size_t size)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vlistxattr(path, list, size, ctx); },
        "listxattr",
        __LINE__,
        {{"path", {path}},
         op->allow_sensitive_logging()
             ? trace::WrappedFuseArg{"list", trace::PlainRawBuffer{list, size}}
             : trace::WrappedFuseArg{"list", trace::RedactedRawBuffer{list, size}},
         {"size", {size}}});
}
int FuseHighLevelOpsBase::static_getxattr(
    const char* path, const char* name, char* value, size_t size, uint32_t position)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]()
        {
            try
            {
                return op->vgetxattr(path, name, value, size, position, ctx);
            }
            catch (const ExceptionBase& e)
            {
                auto err = e.error_number();
#ifdef ENOATTR
                // This happens so frequently that we don't want to log it.
                if (err == ENOATTR)
                {
                    return -err;
                }
#endif
#ifdef ENODATA
                // This happens so frequently that we don't want to log it.
                if (err == ENODATA)
                {
                    return -err;
                }
#endif
                throw;
            }
        },
        "getxattr",
        __LINE__,
        {{"path", {path}},
         {"name", {name}},
         op->allow_sensitive_logging()
             ? trace::WrappedFuseArg{"value", trace::PlainRawBuffer{value, size}}
             : trace::WrappedFuseArg{"value", trace::RedactedRawBuffer{value, size}},
         {"size", {size}},
         {"position", {position}}});
}
int FuseHighLevelOpsBase::static_setxattr(const char* path,
                                          const char* name,
                                          const char* value,
                                          size_t size,
                                          int flags,
                                          uint32_t position)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vsetxattr(path, name, value, size, flags, position, ctx); },
        "setxattr",
        __LINE__,
        {{"path", {path}},
         {"name", {name}},
         op->allow_sensitive_logging()
             ? trace::WrappedFuseArg{"value", trace::PlainRawBuffer{value, size}}
             : trace::WrappedFuseArg{"value", trace::RedactedRawBuffer{value, size}},
         {"size", {size}},
         {"flags", {flags}},
         {"position", {position}}});
}
int FuseHighLevelOpsBase::static_removexattr(const char* path, const char* name)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]() { return op->vremovexattr(path, name, ctx); },
                                          "removexattr",
                                          __LINE__,
                                          {{"path", {path}}, {"name", {name}}});
}

int FuseHighLevelOpsBase::static_getpath(const char* path,
                                         char* buf,
                                         size_t size,
                                         fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call([=]()
                                          { return op->vgetpath(path, buf, size, info, ctx); },
                                          "getpath",
                                          __LINE__,
                                          {{"path", {path}},
                                           {"buf", {static_cast<const void*>(buf)}},
                                           {"size", {size}},
                                           {"info", {info}}});
}

int FuseHighLevelOpsBase::static_ioctl(
    const char* path, int cmd, void* arg, fuse_file_info* fi, unsigned int flags, void* data)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return trace::FuseTracer::traced_call(
        [=]() { return op->vioctl(path, cmd, arg, fi, flags, data, ctx); },
        "ioctl",
        __LINE__,
        {{"path", {path}},
         {"cmd", {cmd}},
         {"arg", {static_cast<const void*>(arg)}},
         {"fi", {fi}},
         {"flags", {flags}},
         {"data", {static_cast<const void*>(data)}}});
}

namespace
{
    void enable_if_capable(fuse_conn_info* info, int cap)
    {
        if (info->capable & cap)
        {
            info->want |= cap;
        }
    }
}    // namespace

fuse_operations FuseHighLevelOpsBase::build_ops(const FuseHighLevelOpsBase* op)
{
    fuse_operations opt{};

    opt.flag_nopath = true;
    opt.flag_nullpath_ok = true;

    opt.init = [](fuse_conn_info* info) -> void*
    {
#ifdef FUSE_CAP_ASYNC_READ
        enable_if_capable(info, FUSE_CAP_ASYNC_READ);
#endif
#ifdef FUSE_CAP_ATOMIC_O_TRUNC
        enable_if_capable(info, FUSE_CAP_ATOMIC_O_TRUNC);
#endif
#ifdef FUSE_CAP_BIG_WRITES
        enable_if_capable(info, FUSE_CAP_BIG_WRITES);
#endif
#ifdef FUSE_CAP_CACHE_SYMLINKS
        enable_if_capable(info, FUSE_CAP_CACHE_SYMLINKS);
#endif
#ifdef FUSE_CAP_WRITEBACK_CACHE
        enable_if_capable(info, FUSE_CAP_WRITEBACK_CACHE);
#endif
#ifdef FUSE_CAP_IOCTL_DIR
        enable_if_capable(info, FUSE_CAP_IOCTL_DIR);
#endif
        auto op = static_cast<FuseHighLevelOpsBase*>(fuse_get_context()->private_data);
        op->initialize(info);
        INFO_LOG("Fuse operations initialized");
        TRACE_LOG("Initalize with fuse op class %s", typeid(*op).name());
        return op;
    };
    opt.destroy = [](void* data) { INFO_LOG("Fuse operations destroyed"); };
    opt.statfs = op->has_statfs() ? &FuseHighLevelOpsBase::static_statfs : nullptr;
    opt.getattr = op->has_getattr() ? &FuseHighLevelOpsBase::static_getattr : nullptr;
    opt.fgetattr = op->has_fgetattr() ? &FuseHighLevelOpsBase::static_fgetattr : nullptr;
    opt.opendir = op->has_opendir() ? &FuseHighLevelOpsBase::static_opendir : nullptr;
    opt.releasedir = op->has_releasedir() ? &FuseHighLevelOpsBase::static_releasedir : nullptr;
    opt.readdir = op->has_readdir() ? &FuseHighLevelOpsBase::static_readdir : nullptr;
    opt.create = op->has_create() ? &FuseHighLevelOpsBase::static_create : nullptr;
    opt.open = op->has_open() ? &FuseHighLevelOpsBase::static_open : nullptr;
    opt.release = op->has_release() ? &FuseHighLevelOpsBase::static_release : nullptr;
    opt.read = op->has_read() ? &FuseHighLevelOpsBase::static_read : nullptr;
    opt.write = op->has_write() ? &FuseHighLevelOpsBase::static_write : nullptr;
    opt.flush = op->has_flush() ? &FuseHighLevelOpsBase::static_flush : nullptr;
    opt.truncate = op->has_truncate() ? &FuseHighLevelOpsBase::static_truncate : nullptr;
    opt.ftruncate = op->has_ftruncate() ? &FuseHighLevelOpsBase::static_ftruncate : nullptr;
    opt.unlink = op->has_unlink() ? &FuseHighLevelOpsBase::static_unlink : nullptr;
    opt.mkdir = op->has_mkdir() ? &FuseHighLevelOpsBase::static_mkdir : nullptr;
    opt.rmdir = op->has_rmdir() ? &FuseHighLevelOpsBase::static_rmdir : nullptr;
    opt.symlink = op->has_symlink() ? &FuseHighLevelOpsBase::static_symlink : nullptr;
    opt.readlink = op->has_readlink() ? &FuseHighLevelOpsBase::static_readlink : nullptr;
    opt.chmod = op->has_chmod() ? &FuseHighLevelOpsBase::static_chmod : nullptr;
    opt.chown = op->has_chown() ? &FuseHighLevelOpsBase::static_chown : nullptr;
    opt.link = op->has_link() ? &FuseHighLevelOpsBase::static_link : nullptr;
#ifdef _WIN32
    opt.getpath = op->has_getpath() ? &FuseHighLevelOpsBase::static_getpath : nullptr;
#endif
    opt.rename = op->has_rename() ? &FuseHighLevelOpsBase::static_rename : nullptr;
    opt.fsync = op->has_fsync() ? &FuseHighLevelOpsBase::static_fsync : nullptr;
    opt.utimens = op->has_utimens() ? &FuseHighLevelOpsBase::static_utimens : nullptr;
    opt.listxattr = op->has_listxattr() ? &FuseHighLevelOpsBase::static_listxattr : nullptr;
    opt.getxattr = op->has_getxattr()
        ? static_cast<decltype(opt.getxattr)>(&FuseHighLevelOpsBase::static_getxattr)
        : nullptr;
    opt.setxattr = op->has_setxattr()
        ? static_cast<decltype(opt.setxattr)>(&FuseHighLevelOpsBase::static_setxattr)
        : nullptr;
    opt.removexattr = op->has_removexattr() ? &FuseHighLevelOpsBase::static_removexattr : nullptr;
    opt.ioctl = op->has_ioctl() ? &FuseHighLevelOpsBase::static_ioctl : nullptr;
    return opt;
}

// DelegateFuseHighLevelOps implementation
DelegateFuseHighLevelOps::DelegateFuseHighLevelOps(std::shared_ptr<FuseHighLevelOpsBase> delegate)
    : delegate_(std::move(delegate))
{
}

bool DelegateFuseHighLevelOps::allow_sensitive_logging() const
{
    return delegate_->allow_sensitive_logging();
}

void DelegateFuseHighLevelOps::initialize(fuse_conn_info* info) { delegate_->initialize(info); }

bool DelegateFuseHighLevelOps::has_statfs() const { return delegate_->has_statfs(); }
int DelegateFuseHighLevelOps::vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx)
{
    return delegate_->vstatfs(path, buf, ctx);
}

bool DelegateFuseHighLevelOps::has_getattr() const { return delegate_->has_getattr(); }
int DelegateFuseHighLevelOps::vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx)
{
    return delegate_->vgetattr(path, st, ctx);
}

bool DelegateFuseHighLevelOps::has_fgetattr() const { return delegate_->has_fgetattr(); }
int DelegateFuseHighLevelOps::vfgetattr(const char* path,
                                        fuse_stat* st,
                                        fuse_file_info* info,
                                        const fuse_context* ctx)
{
    return delegate_->vfgetattr(path, st, info, ctx);
}

bool DelegateFuseHighLevelOps::has_opendir() const { return delegate_->has_opendir(); }
int DelegateFuseHighLevelOps::vopendir(const char* path,
                                       fuse_file_info* info,
                                       const fuse_context* ctx)
{
    return delegate_->vopendir(path, info, ctx);
}

bool DelegateFuseHighLevelOps::has_releasedir() const { return delegate_->has_releasedir(); }
int DelegateFuseHighLevelOps::vreleasedir(const char* path,
                                          fuse_file_info* info,
                                          const fuse_context* ctx)
{
    return delegate_->vreleasedir(path, info, ctx);
}

bool DelegateFuseHighLevelOps::has_readdir() const { return delegate_->has_readdir(); }
int DelegateFuseHighLevelOps::vreaddir(const char* path,
                                       void* buf,
                                       fuse_fill_dir_t filler,
                                       fuse_off_t off,
                                       fuse_file_info* info,
                                       const fuse_context* ctx)
{
    return delegate_->vreaddir(path, buf, filler, off, info, ctx);
}

bool DelegateFuseHighLevelOps::has_create() const { return delegate_->has_create(); }
int DelegateFuseHighLevelOps::vcreate(const char* path,
                                      fuse_mode_t mode,
                                      fuse_file_info* info,
                                      const fuse_context* ctx)
{
    return delegate_->vcreate(path, mode, info, ctx);
}

bool DelegateFuseHighLevelOps::has_open() const { return delegate_->has_open(); }
int DelegateFuseHighLevelOps::vopen(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    return delegate_->vopen(path, info, ctx);
}

bool DelegateFuseHighLevelOps::has_release() const { return delegate_->has_release(); }
int DelegateFuseHighLevelOps::vrelease(const char* path,
                                       fuse_file_info* info,
                                       const fuse_context* ctx)
{
    return delegate_->vrelease(path, info, ctx);
}

bool DelegateFuseHighLevelOps::has_read() const { return delegate_->has_read(); }
int DelegateFuseHighLevelOps::vread(const char* path,
                                    char* buf,
                                    size_t size,
                                    fuse_off_t offset,
                                    fuse_file_info* info,
                                    const fuse_context* ctx)
{
    return delegate_->vread(path, buf, size, offset, info, ctx);
}

bool DelegateFuseHighLevelOps::has_write() const { return delegate_->has_write(); }
int DelegateFuseHighLevelOps::vwrite(const char* path,
                                     const char* buf,
                                     size_t size,
                                     fuse_off_t offset,
                                     fuse_file_info* info,
                                     const fuse_context* ctx)
{
    return delegate_->vwrite(path, buf, size, offset, info, ctx);
}

bool DelegateFuseHighLevelOps::has_flush() const { return delegate_->has_flush(); }
int DelegateFuseHighLevelOps::vflush(const char* path,
                                     fuse_file_info* info,
                                     const fuse_context* ctx)
{
    return delegate_->vflush(path, info, ctx);
}

bool DelegateFuseHighLevelOps::has_ftruncate() const { return delegate_->has_ftruncate(); }
int DelegateFuseHighLevelOps::vftruncate(const char* path,
                                         fuse_off_t len,
                                         fuse_file_info* info,
                                         const fuse_context* ctx)
{
    return delegate_->vftruncate(path, len, info, ctx);
}

bool DelegateFuseHighLevelOps::has_unlink() const { return delegate_->has_unlink(); }
int DelegateFuseHighLevelOps::vunlink(const char* path, const fuse_context* ctx)
{
    return delegate_->vunlink(path, ctx);
}

bool DelegateFuseHighLevelOps::has_mkdir() const { return delegate_->has_mkdir(); }
int DelegateFuseHighLevelOps::vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    return delegate_->vmkdir(path, mode, ctx);
}

bool DelegateFuseHighLevelOps::has_rmdir() const { return delegate_->has_rmdir(); }
int DelegateFuseHighLevelOps::vrmdir(const char* path, const fuse_context* ctx)
{
    return delegate_->vrmdir(path, ctx);
}

bool DelegateFuseHighLevelOps::has_chmod() const { return delegate_->has_chmod(); }
int DelegateFuseHighLevelOps::vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    return delegate_->vchmod(path, mode, ctx);
}

bool DelegateFuseHighLevelOps::has_chown() const { return delegate_->has_chown(); }
int DelegateFuseHighLevelOps::vchown(const char* path,
                                     fuse_uid_t uid,
                                     fuse_gid_t gid,
                                     const fuse_context* ctx)
{
    return delegate_->vchown(path, uid, gid, ctx);
}

bool DelegateFuseHighLevelOps::has_symlink() const { return delegate_->has_symlink(); }
int DelegateFuseHighLevelOps::vsymlink(const char* to, const char* from, const fuse_context* ctx)
{
    return delegate_->vsymlink(to, from, ctx);
}

bool DelegateFuseHighLevelOps::has_link() const { return delegate_->has_link(); }
int DelegateFuseHighLevelOps::vlink(const char* src, const char* dest, const fuse_context* ctx)
{
    return delegate_->vlink(src, dest, ctx);
}

bool DelegateFuseHighLevelOps::has_readlink() const { return delegate_->has_readlink(); }
int DelegateFuseHighLevelOps::vreadlink(const char* path,
                                        char* buf,
                                        size_t size,
                                        const fuse_context* ctx)
{
    return delegate_->vreadlink(path, buf, size, ctx);
}

bool DelegateFuseHighLevelOps::has_rename() const { return delegate_->has_rename(); }
int DelegateFuseHighLevelOps::vrename(const char* from, const char* to, const fuse_context* ctx)
{
    return delegate_->vrename(from, to, ctx);
}

bool DelegateFuseHighLevelOps::has_fsync() const { return delegate_->has_fsync(); }
int DelegateFuseHighLevelOps::vfsync(const char* path,
                                     int datasync,
                                     fuse_file_info* info,
                                     const fuse_context* ctx)
{
    return delegate_->vfsync(path, datasync, info, ctx);
}

bool DelegateFuseHighLevelOps::has_truncate() const { return delegate_->has_truncate(); }
int DelegateFuseHighLevelOps::vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx)
{
    return delegate_->vtruncate(path, len, ctx);
}

bool DelegateFuseHighLevelOps::has_utimens() const { return delegate_->has_utimens(); }
int DelegateFuseHighLevelOps::vutimens(const char* path,
                                       const fuse_timespec* ts,
                                       const fuse_context* ctx)
{
    return delegate_->vutimens(path, ts, ctx);
}

bool DelegateFuseHighLevelOps::has_listxattr() const { return delegate_->has_listxattr(); }
int DelegateFuseHighLevelOps::vlistxattr(const char* path,
                                         char* list,
                                         size_t size,
                                         const fuse_context* ctx)
{
    return delegate_->vlistxattr(path, list, size, ctx);
}

bool DelegateFuseHighLevelOps::has_getxattr() const { return delegate_->has_getxattr(); }
int DelegateFuseHighLevelOps::vgetxattr(const char* path,
                                        const char* name,
                                        char* value,
                                        size_t size,
                                        uint32_t position,
                                        const fuse_context* ctx)
{
    return delegate_->vgetxattr(path, name, value, size, position, ctx);
}

bool DelegateFuseHighLevelOps::has_setxattr() const { return delegate_->has_setxattr(); }
int DelegateFuseHighLevelOps::vsetxattr(const char* path,
                                        const char* name,
                                        const char* value,
                                        size_t size,
                                        int flags,
                                        uint32_t position,
                                        const fuse_context* ctx)
{
    return delegate_->vsetxattr(path, name, value, size, flags, position, ctx);
}

bool DelegateFuseHighLevelOps::has_removexattr() const { return delegate_->has_removexattr(); }
int DelegateFuseHighLevelOps::vremovexattr(const char* path,
                                           const char* name,
                                           const fuse_context* ctx)
{
    return delegate_->vremovexattr(path, name, ctx);
}

bool DelegateFuseHighLevelOps::has_getpath() const { return delegate_->has_getpath(); }
int DelegateFuseHighLevelOps::vgetpath(
    const char* path, char* buf, size_t size, fuse_file_info* info, const fuse_context* ctx)
{
    return delegate_->vgetpath(path, buf, size, info, ctx);
}

bool DelegateFuseHighLevelOps::has_ioctl() const { return delegate_->has_ioctl(); }

int DelegateFuseHighLevelOps::vioctl(const char* path,
                                     int cmd,
                                     void* arg,
                                     struct fuse_file_info* fi,
                                     unsigned int flags,
                                     void* data,
                                     const fuse_context* ctx)
{
    return delegate_->vioctl(path, cmd, arg, fi, flags, data, ctx);
}

// AllowSensitiveLoggingFuseHighLevelOps implementation
AllowSensitiveLoggingFuseHighLevelOps::AllowSensitiveLoggingFuseHighLevelOps(
    std::shared_ptr<FuseHighLevelOpsBase> delegate)
    : DelegateFuseHighLevelOps(std::move(delegate))
{
}

bool AllowSensitiveLoggingFuseHighLevelOps::allow_sensitive_logging() const { return true; }

class SpecialIoctlFuseHighLevelOps : public DelegateFuseHighLevelOps
{
public:
    using DelegateFuseHighLevelOps::DelegateFuseHighLevelOps;

    int vioctl(const char* path,
               int cmd,
               void* arg,
               struct fuse_file_info* fi,
               unsigned int flags,
               void* data,
               const fuse_context* ctx) override
    {
        if (cmd == OSService::get_cmd_for_query_ioctl())
        {
#ifdef _IOC_SIZE
            if (_IOC_SIZE(cmd) != sizeof(unsigned))
            {
                throw_runtime_error("Invalid coding for ioctl!!! A programming error!!!");
            }
#endif
            *(unsigned*)data = OSService::get_magic_for_mounted_status();
            TRACE_LOG("Received request for magic status");
            return 0;
        }
        else if (cmd == OSService::get_cmd_for_trigger_unmount_ioctl())
        {
            TRACE_LOG("Received request for clean exit");
            securefs::clean_exit_fuse();
            return 0;
        }
        int delegate_result
            = DelegateFuseHighLevelOps::vioctl(path, cmd, arg, fi, flags, data, ctx);
        return delegate_result == -ENOSYS ? -ENOTSUP : delegate_result;
    }

    bool has_ioctl() const override { return true; }
};

class SpecialFiledFuseHighLevelOps : public DelegateFuseHighLevelOps
{
public:
    // The special file name is 60 of U+100000.
    // It is longer than most file names, and it is a private use character. So no sane program
    // should use it.
    static constexpr std::string_view kSpecialFileName
        = "\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80"
          "\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80"
          "\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80"
          "\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80"
          "\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80"
          "\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80"
          "\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80"
          "\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80"
          "\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80"
          "\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80"
          "\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80\xf4\x80\x80\x80";

public:
    using DelegateFuseHighLevelOps::DelegateFuseHighLevelOps;

    int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) override;

    int vrmdir(const char* path, const fuse_context* ctx) override;

    bool has_getattr() const override { return true; }
    bool has_rmdir() const override { return true; }
};

int SpecialFiledFuseHighLevelOps::vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx)
{
    if (path && path[0] == '/' && path + 1 == kSpecialFileName)
    {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0777;
        st->st_nlink = 2;
        st->st_uid = ctx->uid;
        st->st_gid = ctx->gid;
        return 0;
    }
    return DelegateFuseHighLevelOps::vgetattr(path, st, ctx);
}

int SpecialFiledFuseHighLevelOps::vrmdir(const char* path, const fuse_context* ctx)
{
    if (path && path[0] == '/' && path + 1 == kSpecialFileName)
    {
        clean_exit_fuse();
        return 0;
    }
    return DelegateFuseHighLevelOps::vrmdir(path, ctx);
}

std::shared_ptr<FuseHighLevelOpsBase>
wrap_as_unmountable_fuse(std::shared_ptr<FuseHighLevelOpsBase> ops)
{
    if (is_fuse_t())
    {
        return std::make_shared<SpecialFiledFuseHighLevelOps>(std::move(ops));
    }
    return std::make_shared<SpecialIoctlFuseHighLevelOps>(std::move(ops));
}

bool is_mounted_by_fuse(std::string_view path)
{
    try
    {
        if (is_fuse_t())
        {
            fuse_stat st{};
            OSService(std::string(path))
                .stat(std::string(SpecialFiledFuseHighLevelOps::kSpecialFileName), &st);
            return (st.st_mode & S_IFMT) == S_IFDIR;
        }
        return OSService(std::string(path)).query_if_mounted_by_ioctl();
    }
    catch (const ExceptionBase&)
    {
        return false;
    }
}
void trigger_unmount_by_fuse(std::string_view path)
{
    if (is_fuse_t())
    {
        OSService(std::string(path))
            .remove_directory_nothrow(std::string(SpecialFiledFuseHighLevelOps::kSpecialFileName));
    }
    else
    {
        OSService(std::string(path)).trigger_unmount_by_ioctl();
    }
}

}    // namespace securefs
