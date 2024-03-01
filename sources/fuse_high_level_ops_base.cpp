#include "fuse_high_level_ops_base.h"
#include "fuse_tracer.h"
#include "logger.h"

#include <absl/functional/function_ref.h>

namespace securefs
{
int FuseHighLevelOpsBase::static_statfs(const char* path, fuse_statvfs* buf)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vstatfs(path, buf, ctx); }, "statfs", __LINE__, {{path}, {buf}});
}
int FuseHighLevelOpsBase::static_getattr(const char* path, fuse_stat* st)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vgetattr(path, st, ctx); }, "getattr", __LINE__, {{path}, {st}});
}
int FuseHighLevelOpsBase::static_fgetattr(const char* path, fuse_stat* st, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vfgetattr(path, st, info, ctx); },
                                   "fgetattr",
                                   __LINE__,
                                   {{path}, {st}, {info}});
}
int FuseHighLevelOpsBase::static_opendir(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vopendir(path, info, ctx); }, "opendir", __LINE__, {{path}, {info}});
}
int FuseHighLevelOpsBase::static_releasedir(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vreleasedir(path, info, ctx); },
                                   "releasedir",
                                   __LINE__,
                                   {{path}, {info}});
}
int FuseHighLevelOpsBase::static_readdir(
    const char* path, void* buf, fuse_fill_dir_t filler, fuse_off_t off, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]()
                                   { return op->vreaddir(path, buf, filler, off, info, ctx); },
                                   "readdir",
                                   __LINE__,
                                   {{path}, {buf}, {&filler}, {&off}, {info}});
}
int FuseHighLevelOpsBase::static_create(const char* path, fuse_mode_t mode, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vcreate(path, mode, info, ctx); },
                                   "create",
                                   __LINE__,
                                   {{path}, {&mode}, {info}});
}
int FuseHighLevelOpsBase::static_open(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vopen(path, info, ctx); }, "open", __LINE__, {{path}, {info}});
}
int FuseHighLevelOpsBase::static_release(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vrelease(path, info, ctx); }, "release", __LINE__, {{path}, {info}});
}
int FuseHighLevelOpsBase::static_read(
    const char* path, char* buf, size_t size, fuse_off_t offset, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vread(path, buf, size, offset, info, ctx); },
        "read",
        __LINE__,
        {{path}, {static_cast<const void*>(buf)}, {&size}, {&offset}, {info}});
}
int FuseHighLevelOpsBase::static_write(
    const char* path, const char* buf, size_t size, fuse_off_t offset, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vwrite(path, buf, size, offset, info, ctx); },
        "write",
        __LINE__,
        {{path}, {static_cast<const void*>(buf)}, {&size}, {&offset}, {info}});
}
int FuseHighLevelOpsBase::static_flush(const char* path, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vflush(path, info, ctx); }, "flush", __LINE__, {{path}, {info}});
}
int FuseHighLevelOpsBase::static_ftruncate(const char* path, fuse_off_t len, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vftruncate(path, len, info, ctx); },
                                   "ftruncate",
                                   __LINE__,
                                   {{path}, {&len}, {info}});
}
int FuseHighLevelOpsBase::static_unlink(const char* path)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vunlink(path, ctx); }, "unlink", __LINE__, {{path}});
}
int FuseHighLevelOpsBase::static_mkdir(const char* path, fuse_mode_t mode)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vmkdir(path, mode, ctx); }, "mkdir", __LINE__, {{path}, {&mode}});
}
int FuseHighLevelOpsBase::static_rmdir(const char* path)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vrmdir(path, ctx); }, "rmdir", __LINE__, {{path}});
}
int FuseHighLevelOpsBase::static_chmod(const char* path, fuse_mode_t mode)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vchmod(path, mode, ctx); }, "chmod", __LINE__, {{path}, {&mode}});
}
int FuseHighLevelOpsBase::static_chown(const char* path, fuse_uid_t uid, fuse_gid_t gid)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vchown(path, uid, gid, ctx); },
                                   "chown",
                                   __LINE__,
                                   {{path}, {&uid}, {&gid}});
}
int FuseHighLevelOpsBase::static_symlink(const char* to, const char* from)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vsymlink(to, from, ctx); }, "symlink", __LINE__, {{to}, {from}});
}
int FuseHighLevelOpsBase::static_link(const char* src, const char* dest)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vlink(src, dest, ctx); }, "link", __LINE__, {{src}, {dest}});
}
int FuseHighLevelOpsBase::static_readlink(const char* path, char* buf, size_t size)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vreadlink(path, buf, size, ctx); },
                                   "readlink",
                                   __LINE__,
                                   {{path}, {static_cast<const void*>(buf)}, {&size}});
}
int FuseHighLevelOpsBase::static_rename(const char* from, const char* to)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vrename(from, to, ctx); }, "rename", __LINE__, {{from}, {to}});
}
int FuseHighLevelOpsBase::static_fsync(const char* path, int datasync, fuse_file_info* info)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vfsync(path, datasync, info, ctx); },
                                   "fsync",
                                   __LINE__,
                                   {{path}, {&datasync}, {info}});
}
int FuseHighLevelOpsBase::static_truncate(const char* path, fuse_off_t len)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vtruncate(path, len, ctx); }, "truncate", __LINE__, {{path}, {&len}});
}
int FuseHighLevelOpsBase::static_utimens(const char* path, const fuse_timespec* ts)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vutimens(path, ts, ctx); }, "utimens", __LINE__, {{path}, {ts}});
}
int FuseHighLevelOpsBase::static_listxattr(const char* path, char* list, size_t size)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vlistxattr(path, list, size, ctx); },
                                   "listxattr",
                                   __LINE__,
                                   {{path}, {list}, {&size}});
}
int FuseHighLevelOpsBase::static_getxattr(
    const char* path, const char* name, char* value, size_t size, uint32_t position)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call(
        [=]() { return op->vgetxattr(path, name, value, size, position, ctx); },
        "getxattr",
        __LINE__,
        {{path}, {name}, {value}, {&size}, {&position}});
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
    return FuseTracer::traced_call(
        [=]() { return op->vsetxattr(path, name, value, size, flags, position, ctx); },
        "setxattr",
        __LINE__,
        {{path}, {name}, {value}, {&size}, {&flags}, {&position}});
}
int FuseHighLevelOpsBase::static_removexattr(const char* path, const char* name)
{
    auto ctx = fuse_get_context();
    auto op = static_cast<FuseHighLevelOpsBase*>(ctx->private_data);
    return FuseTracer::traced_call([=]() { return op->vremovexattr(path, name, ctx); },
                                   "removexattr",
                                   __LINE__,
                                   {{path}, {name}});
}

fuse_operations FuseHighLevelOpsBase::build_ops(bool enable_xattr)
{
    fuse_operations opt{};

    opt.flag_nopath = true;
    opt.flag_nullpath_ok = true;

    opt.init = [](fuse_conn_info* info) -> void*
    {
        void* args = fuse_get_context()->private_data;
        auto op = (*static_cast<InitialDataType*>(args))();
        op->initialize(info);
        TRACE_LOG("Initalize with fuse op class %s", typeid(*op).name());
        return op.release();
    };
    opt.destroy = [](void* data)
    {
        TRACE_LOG("Destroy");
        delete static_cast<FuseHighLevelOpsBase*>(data);
    };
    opt.statfs = &FuseHighLevelOpsBase::static_statfs;
    opt.getattr = &FuseHighLevelOpsBase::static_getattr;
    opt.fgetattr = &FuseHighLevelOpsBase::static_fgetattr;
    opt.opendir = &FuseHighLevelOpsBase::static_opendir;
    opt.releasedir = &FuseHighLevelOpsBase::static_releasedir;
    opt.readdir = &FuseHighLevelOpsBase::static_readdir;
    opt.create = &FuseHighLevelOpsBase::static_create;
    opt.open = &FuseHighLevelOpsBase::static_open;
    opt.release = &FuseHighLevelOpsBase::static_release;
    opt.read = &FuseHighLevelOpsBase::static_read;
    opt.write = &FuseHighLevelOpsBase::static_write;
    opt.flush = &FuseHighLevelOpsBase::static_flush;
    opt.truncate = &FuseHighLevelOpsBase::static_truncate;
    opt.ftruncate = &FuseHighLevelOpsBase::static_ftruncate;
    opt.unlink = &FuseHighLevelOpsBase::static_unlink;
    opt.mkdir = &FuseHighLevelOpsBase::static_mkdir;
    opt.rmdir = &FuseHighLevelOpsBase::static_rmdir;
#ifndef _WIN32
    opt.chmod = &FuseHighLevelOpsBase::static_chmod;
    opt.chown = &FuseHighLevelOpsBase::static_chown;
    opt.symlink = &FuseHighLevelOpsBase::static_symlink;
    opt.link = &FuseHighLevelOpsBase::static_link;
    opt.readlink = &FuseHighLevelOpsBase::static_readlink;
#endif
    opt.rename = &FuseHighLevelOpsBase::static_rename;
    opt.fsync = &FuseHighLevelOpsBase::static_fsync;
    opt.utimens = &FuseHighLevelOpsBase::static_utimens;

    if (!enable_xattr)
        return opt;

#ifdef __APPLE__
    opt.listxattr = &FuseHighLevelOpsBase::static_listxattr;
    opt.getxattr = &FuseHighLevelOpsBase::static_getxattr;
    opt.setxattr = &FuseHighLevelOpsBase::static_setxattr;
    opt.removexattr = &FuseHighLevelOpsBase::static_removexattr;
#endif
    return opt;
}

}    // namespace securefs
