#include "full_format.h"
#include "exceptions.h"
#include "files.h"
#include "lock_guard.h"
#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <cerrno>
#include <cstdint>

namespace securefs::full_format
{
int FuseHighLevelOps::vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx)
{
    root_.statfs(buf);
    return 0;
};
int FuseHighLevelOps::vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard lg(**opened);
    (**opened).stat(st);
    return 0;
};
int FuseHighLevelOps::vfgetattr(const char* path,
                                fuse_stat* st,
                                fuse_file_info* info,
                                const fuse_context* ctx)
{
    auto fp = get_file(info);
    FileLockGuard lg(*fp);
    fp->stat(st);
    return 0;
};
int FuseHighLevelOps::vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    if ((**opened).type() != Directory::class_type())
    {
        return -ENOTDIR;
    }
    set_file(info, opened->release());
    return 0;
};
int FuseHighLevelOps::vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto fp = get_file(info);
    if (fp->type() != Directory::class_type())
    {
        return -ENOTDIR;
    }
    FilePtrHolder holder(fp, FileTableCloser(&ft_));
    // Let destructor does its job.
    return 0;
};
int FuseHighLevelOps::vreaddir(const char* path,
                               void* buf,
                               fuse_fill_dir_t filler,
                               fuse_off_t off,
                               fuse_file_info* info,
                               const fuse_context* ctx)
{
    auto fp = get_file(info);
    if (fp->type() != Directory::class_type())
    {
        return -ENOTDIR;
    }
    fuse_stat st{};
    FileLockGuard lg(*fp);

    st.st_ino = to_inode_number(fp->get_id());
    st.st_mode = S_IFDIR;
    filler(buf, ".", &st, 0);

    st.st_ino = fp->get_parent_ino();
    filler(buf, "..", &st, 0);

    fp->cast_as<Directory>()->iterate_over_entries(
        [&](const std::string& name, const id_type& id, int type) -> bool
        {
            st.st_mode = FileBase::mode_for_type(type);
            st.st_ino = to_inode_number(id);
            bool success = filler(buf, name.c_str(), &st, 0) == 0;
            if (!success)
            {
                WARN_LOG("Filling directory buffer failed");
            }
            return success;
        });
    return 0;
};
int FuseHighLevelOps::vcreate(const char* path,
                              fuse_mode_t mode,
                              fuse_file_info* info,
                              const fuse_context* ctx)
{
    auto holder = create(path, mode, RegularFile::class_type());
    set_file(info, holder.release());
    return -ENOSYS;
};
int FuseHighLevelOps::vopen(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    if (info->flags & O_TRUNC)
    {
        FileLockGuard lg(**opened);
        (**opened).cast_as<RegularFile>()->truncate(0);
    }
    set_file(info, opened->release());
    return 0;
};
int FuseHighLevelOps::vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto fp = get_file(info);
    if (fp->type() != RegularFile::class_type())
    {
        return -EINVAL;
    }
    FilePtrHolder holder(fp, FileTableCloser(&ft_));
    // Let destructor does its job.
    return 0;
};
int FuseHighLevelOps::vread(const char* path,
                            char* buf,
                            size_t size,
                            fuse_off_t offset,
                            fuse_file_info* info,
                            const fuse_context* ctx)
{
    auto fp = get_file(info);
    FileLockGuard lg(*fp);
    return static_cast<int>(fp->cast_as<RegularFile>()->read(buf, offset, size));
};
int FuseHighLevelOps::vwrite(const char* path,
                             const char* buf,
                             size_t size,
                             fuse_off_t offset,
                             fuse_file_info* info,
                             const fuse_context* ctx)
{
    auto fp = get_file(info);
    FileLockGuard lg(*fp);
    fp->cast_as<RegularFile>()->write(buf, offset, size);
    return static_cast<int>(size);
};
int FuseHighLevelOps::vflush(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto fp = get_file(info);
    FileLockGuard lg(*fp);
    fp->flush();
    return 0;
};
int FuseHighLevelOps::vftruncate(const char* path,
                                 fuse_off_t len,
                                 fuse_file_info* info,
                                 const fuse_context* ctx)
{
    auto fp = get_file(info);
    FileLockGuard lg(*fp);
    fp->cast_as<RegularFile>()->truncate(len);
    return 0;
};
int FuseHighLevelOps::vunlink(const char* path, const fuse_context* ctx)
{
    auto [dirholder, last_component] = open_base(path);
    id_type id;
    int type;

    {
        FileLockGuard lg(*dirholder);
        if (!dirholder->cast_as<Directory>()->remove_entry(last_component, id, type))
        {
            return -ENOENT;
        }
    }

    auto fp = ft_.open_as(id, type);
    FileLockGuard lg(*fp);
    fp->unlink();
    return 0;
};
int FuseHighLevelOps::vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    create(path, mode, Directory::class_type());
    return 0;
};
int FuseHighLevelOps::vrmdir(const char* path, const fuse_context* ctx)
{
    auto [dirholder, last_component] = open_base(path);
    id_type id;
    int type;

    {
        FileLockGuard lg(*dirholder);
        if (!dirholder->cast_as<Directory>()->remove_entry(last_component, id, type))
        {
            return -ENOENT;
        }
    }

    auto fp = ft_.open_as(id, type);
    FileLockGuard lg(*fp);
    fp->cast_as<Directory>()->iterate_over_entries(
        [](const std::string& name, const id_type& id, int type) -> bool
        { throwVFSException(ENOTEMPTY); });
    fp->unlink();
    return 0;
};
int FuseHighLevelOps::vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    (**opened).set_mode((**opened).type() | (mode & 0777));
    return 0;
};
int FuseHighLevelOps::vchown(const char* path,
                             fuse_uid_t uid,
                             fuse_gid_t gid,
                             const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    (**opened).set_uid(uid);
    (**opened).set_gid(gid);
    return 0;
};
int FuseHighLevelOps::vsymlink(const char* to, const char* from, const fuse_context* ctx)
{
    auto holder = create(from, 0644, Symlink::class_type());
    FileLockGuard fg(*holder);
    holder->cast_as<Symlink>()->set(to);
    return 0;
};
int FuseHighLevelOps::vlink(const char* src, const char* dest, const fuse_context* ctx)
{
    auto opened = open_all(src);
    if (!opened)
    {
        return -ENOENT;
    }
    auto [base_dir, last_component] = open_base(dest);
    DoubleFileLockGuard lg(*base_dir, **opened);
    if (base_dir->cast_as<Directory>()->add_entry(
            last_component, (**opened).get_id(), (**opened).get_real_type()))
    {
        (**opened).set_nlink((**opened).get_nlink() + 1);
        return 0;
    }
    return -EEXIST;
};
int FuseHighLevelOps::vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx)
{
    if (!size)
    {
        return -EFAULT;
    }
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    auto destination = (**opened).cast_as<Symlink>()->get();
    memset(buf, 0, size);
    memcpy(buf, destination.data(), std::min(destination.size(), size - 1));
    return 0;
};
int FuseHighLevelOps::vrename(const char* from, const char* to, const fuse_context* ctx)
{
    auto [base_from, last_from] = open_base(from);
    auto [base_to, last_to] = open_base(to);

    id_type id, removed_id;
    int type, removed_type;
    bool should_unlink = false;

    {
        DoubleFileLockGuard lg(*base_from, *base_to);

        if (!base_from->cast_as<Directory>()->get_entry(last_from, id, type))
        {
            return -ENOENT;
        }
        should_unlink
            = base_to->cast_as<Directory>()->remove_entry(last_to, removed_id, removed_type);
        base_to->cast_as<Directory>()->add_entry(last_to, id, type);
    }
    if (should_unlink)
    {
        auto holder = ft_.open_as(removed_id, removed_type);
        FileLockGuard lg(*holder);
        holder->unlink();
    }
    return 0;
};
int FuseHighLevelOps::vfsync(const char* path,
                             int datasync,
                             fuse_file_info* info,
                             const fuse_context* ctx)
{
    auto fp = get_file(info);
    FileLockGuard lg(*fp);
    fp->fsync();
    return 0;
};
int FuseHighLevelOps::vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    (**opened).cast_as<RegularFile>()->truncate(len);
    return 0;
};
int FuseHighLevelOps::vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx)
{
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    (**opened).utimens(ts);
    return 0;
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
