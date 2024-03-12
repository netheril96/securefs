#include "full_format.h"

namespace securefs::full_format
{
int FuseHighLevelOps::vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vfgetattr(const char* path,
                                fuse_stat* st,
                                fuse_file_info* info,
                                const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vreaddir(const char* path,
                               void* buf,
                               fuse_fill_dir_t filler,
                               fuse_off_t off,
                               fuse_file_info* info,
                               const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vcreate(const char* path,
                              fuse_mode_t mode,
                              fuse_file_info* info,
                              const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vopen(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vread(const char* path,
                            char* buf,
                            size_t size,
                            fuse_off_t offset,
                            fuse_file_info* info,
                            const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vwrite(const char* path,
                             const char* buf,
                             size_t size,
                             fuse_off_t offset,
                             fuse_file_info* info,
                             const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vflush(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vftruncate(const char* path,
                                 fuse_off_t len,
                                 fuse_file_info* info,
                                 const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vunlink(const char* path, const fuse_context* ctx) { return -ENOSYS; };
int FuseHighLevelOps::vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vrmdir(const char* path, const fuse_context* ctx) { return -ENOSYS; };
int FuseHighLevelOps::vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vchown(const char* path,
                             fuse_uid_t uid,
                             fuse_gid_t gid,
                             const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vsymlink(const char* to, const char* from, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vlink(const char* src, const char* dest, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vrename(const char* from, const char* to, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vfsync(const char* path,
                             int datasync,
                             fuse_file_info* info,
                             const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vgetxattr(const char* path,
                                const char* name,
                                char* value,
                                size_t size,
                                uint32_t position,
                                const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vsetxattr(const char* path,
                                const char* name,
                                const char* value,
                                size_t size,
                                int flags,
                                uint32_t position,
                                const fuse_context* ctx)
{
    return -ENOSYS;
};
int FuseHighLevelOps::vremovexattr(const char* path, const char* name, const fuse_context* ctx)
{
    return -ENOSYS;
};
}    // namespace securefs::full_format
