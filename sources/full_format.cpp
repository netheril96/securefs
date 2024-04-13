#include "full_format.h"
#include "apple_xattr_workaround.h"
#include "exceptions.h"
#include "files.h"
#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <absl/container/inlined_vector.h>
#include <absl/strings/numbers.h>
#include <absl/strings/str_split.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string>

namespace securefs::full_format
{
void FuseHighLevelOps::initialize(struct fuse_conn_info* conn)
{
    if (!case_insensitive_)
    {
        return;
    }
#ifdef FUSE_CAP_CASE_INSENSITIVE
    if (conn->capable & FUSE_CAP_CASE_INSENSITIVE)
    {
        conn->want |= FUSE_CAP_CASE_INSENSITIVE;
    }
#endif
}
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
        [&](const std::string& name, const id_type& id, int type)
        {
            st.st_mode = FileBase::mode_for_type(type);
            st.st_ino = to_inode_number(id);
            int rc = std::abs(filler(buf, name.c_str(), &st, 0));
            if (rc != 0)
            {
                VERBOSE_LOG("Filling directory buffer failed: %s",
                            OSService::stringify_system_error(rc));
                throwVFSException(rc);
            }
        });
    return 0;
};
int FuseHighLevelOps::vcreate(const char* path,
                              fuse_mode_t mode,
                              fuse_file_info* info,
                              const fuse_context* ctx)
{
    auto holder = create(path, mode, RegularFile::class_type(), ctx->uid, ctx->gid);
    set_file(info, holder.release());
    return 0;
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
    create(path, mode, Directory::class_type(), ctx->uid, ctx->gid);
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
    (**opened).set_mode(((**opened).get_mode() & ~0777u) | (mode & 0777u));
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
    auto holder = create(from, 0644, Symlink::class_type(), ctx->uid, ctx->gid);
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

    id_type from_id, to_id;
    int from_type, to_type;
    bool has_to_item = false;

    {
        DoubleFileLockGuard lg(*base_from, *base_to);

        if (!base_from->cast_as<Directory>()->remove_entry(last_from, from_id, from_type))
        {
            return -ENOENT;
        }
        has_to_item = base_to->cast_as<Directory>()->remove_entry(last_to, to_id, to_type);
        if (has_to_item && from_id == to_id)
        {
            // Cannot rename a hardlink onto itself
            base_from->cast_as<Directory>()->add_entry(last_from, from_id, from_type);
            base_to->cast_as<Directory>()->add_entry(last_to, to_id, to_type);
            return 0;
        }
        base_to->cast_as<Directory>()->add_entry(last_to, from_id, from_type);
    }
    if (has_to_item)
    {
        auto holder = ft_.open_as(to_id, to_type);
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
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    int rc;
    {
        FileLockGuard fg(**opened);
        rc = (**opened).listxattr(list, size);
    }
    transform_listxattr_result(list, size);
    return rc;
};
int FuseHighLevelOps::vgetxattr(const char* path,
                                const char* name,
                                char* value,
                                size_t size,
                                uint32_t position,
                                const fuse_context* ctx)
{
    if (position != 0)
        return -EINVAL;
    if (int rc = precheck_getxattr(&name); rc <= 0)
        return rc;
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    return (**opened).getxattr(name, value, size);
};
int FuseHighLevelOps::vsetxattr(const char* path,
                                const char* name,
                                const char* value,
                                size_t size,
                                int flags,
                                uint32_t position,
                                const fuse_context* ctx)
{
    if (position != 0)
        return -EINVAL;
    if (int rc = precheck_setxattr(&name, &flags); rc <= 0)
        return rc;

    flags &= XATTR_CREATE | XATTR_REPLACE;
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    (**opened).setxattr(name, value, size, flags);
    return 0;
};
int FuseHighLevelOps::vremovexattr(const char* path, const char* name, const fuse_context* ctx)
{
    if (int rc = precheck_removexattr(&name); rc <= 0)
    {
        return rc;
    }
    auto opened = open_all(path);
    if (!opened)
    {
        return -ENOENT;
    }
    FileLockGuard fg(**opened);
    (**opened).removexattr(name);
    return 0;
}
bool FuseHighLevelOps::has_getpath() const { return case_insensitive_; }

int FuseHighLevelOps::vgetpath(
    const char* path, char* buf, size_t size, fuse_file_info* info, const fuse_context* ctx)
{
    auto copy_and_return = [=](std::string_view result)
    {
        if (result.size() >= size)
        {
            return -ENAMETOOLONG;
        }
        std::fill(buf, buf + size, 0);
        std::copy(result.begin(), result.end(), buf);
        return 0;
    };

    if (path[0] == 0 || strcmp(path, "/") == 0)
    {
        return copy_and_return(path);
    }
    absl::InlinedVector<std::string_view, 7> splits = absl::StrSplit(path, '/', absl::SkipEmpty());
    uint64_t parent_ino = to_inode_number(kRootId);
    FilePtrHolder holder = ft_.open_as(kRootId, Directory::class_type());
    for (auto& split : splits)
    {
        id_type id;
        int type;
        std::string_view normed_name;
        {
            FileLockGuard lg(*holder);
            auto get_result = holder->cast_as<Directory>()->get_entry(split, id, type);
            if (!get_result.has_value())
            {
                throwVFSException(ENOENT);
            }
            normed_name = *get_result;
        }
        holder = ft_.open_as(id, type);
        holder->set_parent_ino(parent_ino);
        parent_ino = holder->get_parent_ino();
        split = normed_name;
    }
    std::string result;
    result.reserve(strlen(path) + 31);
    for (auto p : splits)
    {
        result.push_back('/');
        result.append(p.data(), p.size());
    }
    return copy_and_return(result);
};

FuseHighLevelOps::OpenBaseResult FuseHighLevelOps::open_base(absl::string_view path)
{
    absl::InlinedVector<std::string_view, 7> splits = absl::StrSplit(path, '/', absl::SkipEmpty());
    uint64_t parent_ino = to_inode_number(kRootId);
    FilePtrHolder holder = ft_.open_as(kRootId, Directory::class_type());
    for (size_t i = 0; i + 1 < splits.size(); ++i)
    {
        id_type id;
        int type;
        {
            FileLockGuard lg(*holder);
            if (!holder->cast_as<Directory>()->get_entry(splits[i], id, type))
            {
                throwVFSException(ENOENT);
            }
        }
        holder = ft_.open_as(id, type);
        holder->set_parent_ino(parent_ino);
        parent_ino = holder->get_parent_ino();
    }
    return {std::move(holder), splits.empty() ? std::string_view() : splits.back()};
}
FilePtrHolder
FuseHighLevelOps::create(absl::string_view path, unsigned mode, int type, int uid, int gid)
{
    auto [base_dir, last_component] = open_base(path);
    auto holder = ft_.create_as(type);
    {
        FileLockGuard lg(*holder);
        holder->initialize_empty((mode & 0777) | FileBase::mode_for_type(type), uid, gid);
    }
    bool success = false;
    {
        FileLockGuard lg(*base_dir);
        success = base_dir->cast_as<Directory>()->add_entry(last_component, holder->get_id(), type);
    }
    if (!success)
    {
        FileLockGuard lg(*holder);
        holder->unlink();
        throwVFSException(EEXIST);
    }
    holder->set_parent_ino(to_inode_number(base_dir->get_id()));
    return holder;
}
std::optional<FilePtrHolder> FuseHighLevelOps::open_all(absl::string_view path)
{
    if (path.empty() || path == "/")
    {
        return ft_.open_as(kRootId, Directory::class_type());
    }
    auto [base_dir, last_component] = open_base(path);
    bool success = false;
    id_type id;
    int type;

    {
        FileLockGuard lg(*base_dir);
        success = base_dir->cast_as<Directory>()->get_entry(last_component, id, type).has_value();
    }
    if (!success)
    {
        return {};
    }
    auto holder = ft_.open_as(id, type);
    holder->set_parent_ino(to_inode_number(base_dir->get_id()));
    return holder;
}

}    // namespace securefs::full_format
