#include "operations.h"
#include "platform.h"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <string>
#include <typeinfo>
#include <utility>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

using securefs::operations::FileSystemContext;

namespace securefs
{
namespace internal
{
    inline FileSystemContext* get_fs(struct fuse_context* ctx)
    {
        return static_cast<FileSystemContext*>(ctx->private_data);
    }

    typedef AutoClosedFileBase FileGuard;

    FileGuard open_base_dir(FileSystemContext* fs, const char* path, std::string& last_component)
    {
#ifdef WIN32
        std::string norm_path(path);
        for (char& c : norm_path)
        {
            if (c >= 'A' && c <= 'Z')
                c -= 'A' - 'a';
        }
        auto components = split(norm_path.c_str(), '/');
#else
        auto components = split(path, '/');
#endif

        FileGuard result(&fs->table, fs->table.open_as(fs->root_id, FileBase::DIRECTORY));
        if (components.empty())
        {
            last_component = std::string();
            return result;
        }
        id_type id;
        int type;

        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            bool exists = result.get_as<Directory>()->get_entry(components[i], id, type);
            if (!exists)
                throw OSException(ENOENT);
            if (type != FileBase::DIRECTORY)
                throw OSException(ENOTDIR);
            result.reset(fs->table.open_as(id, type));
        }
        last_component = components.back();
        return result;
    }

    FileGuard open_all(FileSystemContext* fs, const char* path)
    {
        std::string last_component;
        auto fg = open_base_dir(fs, path, last_component);
        if (last_component.empty())
            return fg;
        id_type id;
        int type;
        bool exists = fg.get_as<Directory>()->get_entry(last_component, id, type);
        if (!exists)
            throw OSException(ENOENT);
        fg.reset(fs->table.open_as(id, type));
        return fg;
    }

    // Specialization of `open_all` since `OSException(ENOENT)` occurs too frequently
    bool open_all(FileSystemContext* fs, const char* path, FileGuard& fg)
    {
        std::string last_component;
        fg = open_base_dir(fs, path, last_component);
        if (last_component.empty())
            return true;
        id_type id;
        int type;
        bool exists = fg.get_as<Directory>()->get_entry(last_component, id, type);
        if (!exists)
        {
            fg.reset(nullptr);
            return false;
        }
        fg.reset(fs->table.open_as(id, type));
        return true;
    }

    FileGuard create(FileSystemContext* fs, const char* path, int type, uint32_t mode, uint32_t uid, uint32_t gid)
    {
        std::string last_component;
        auto dir = open_base_dir(fs, path, last_component);
        id_type id;
        generate_random(id.data(), id.size());

        FileGuard result(&fs->table, fs->table.create_as(id, type));
        result->initialize_empty(mode, uid, gid);

        try
        {
            bool success = dir.get_as<Directory>()->add_entry(last_component, id, type);
            if (!success)
                throw OSException(EEXIST);
        }
        catch (...)
        {
            result->unlink();
            throw;
        }
        return result;
    }

    void remove(FileSystemContext* fs, const id_type& id, int type)
    {
        try
        {
            FileGuard to_be_removed(&fs->table, fs->table.open_as(id, type));
            to_be_removed->unlink();
        }
        catch (...)
        {
            // Errors in unlinking the actual underlying file can be ignored
            // They will not affect the apparent filesystem operations
        }
    }

    void remove(FileSystemContext* fs, const char* path)
    {
        std::string last_component;
        auto dir_guard = open_base_dir(fs, path, last_component);
        auto dir = dir_guard.get_as<Directory>();
        if (last_component.empty())
            throw OSException(EPERM);
        id_type id;
        int type;
        while (true)
        {
            if (!dir->get_entry(last_component, id, type))
                throw OSException(ENOENT);

            auto&& table = fs->table;
            FileGuard inner_guard(&table, table.open_as(id, type));
            auto inner_fb = inner_guard.get();
            if (inner_fb->type() == FileBase::DIRECTORY
                && !static_cast<Directory*>(inner_fb)->empty())
                throw OSException(ENOTEMPTY);
            dir->remove_entry(last_component, id, type);
            inner_fb->unlink();
            break;
        }
    }

    inline bool is_readonly(struct fuse_context* ctx) { return get_fs(ctx)->table.is_readonly(); }
}

namespace operations
{

    FileSystemContext::FileSystemContext(const MountOptions& opt)
        : table(opt.version.value(),
                opt.root,
                opt.master_key.value(),
                opt.flags.value(),
                opt.block_size.value(),
                opt.iv_size.value())
        , root_id()
        , logger(opt.logger)
        , uid_override(opt.uid_override)
        , gid_override(opt.gid_override)
    {
        block_size = opt.block_size.value();
    }

    FileSystemContext::~FileSystemContext() {}

#define COMMON_PROLOGUE                                                                            \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);                                                               \
    fs->logger->log(LoggingLevel::VERBOSE, "%s (path=%s)", __FUNCTION__, path);

#define COMMON_CATCH_BLOCK                                                                         \
    catch (const CommonException& e) { return -e.error_number(); }                                 \
    catch (const SeriousException& e)                                                              \
    {                                                                                              \
        fs->logger->log(LoggingLevel::ERROR,                                                       \
                        "%s (path=%s) encounters %s: %s",                                          \
                        __FUNCTION__,                                                              \
                        path,                                                                      \
                        e.type_name(),                                                             \
                        e.what());                                                                 \
        return -e.error_number();                                                                  \
    }

    void* init(struct fuse_conn_info*)
    {
        auto args = static_cast<MountOptions*>(fuse_get_context()->private_data);
        auto fs = new FileSystemContext(*args);
        fs->logger->log(LoggingLevel::VERBOSE, "%s", __FUNCTION__);
        fputs("Filesystem mounted successfully\n", stderr);
        return fs;
    }

    void destroy(void* data)
    {
        auto fs = static_cast<FileSystemContext*>(data);
        fs->logger->log(LoggingLevel::VERBOSE, "%s", __FUNCTION__);
        delete fs;
        fputs("Filesystem unmounted successfully\n", stderr);
    }

    int statfs(const char* path, struct statvfs* fs_info)
    {
        COMMON_PROLOGUE
        try
        {
            fs->table.statfs(fs_info);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int getattr(const char* path, FUSE_STAT* st)
    {
        COMMON_PROLOGUE

        try
        {
            if (!st)
                return -EINVAL;

            internal::FileGuard fg(nullptr, nullptr);
            if (!internal::open_all(fs, path, fg))
                return -ENOENT;
            fg->stat(st);
            if (fs->uid_override)
            {
                st->st_uid = *fs->uid_override;
            }
            if (fs->gid_override)
            {
                st->st_gid = *fs->gid_override;
            }
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int releasedir(const char* path, struct fuse_file_info* info)
    {
        return ::securefs::operations::release(path, info);
    }

    int readdir(
        const char* path, void* buffer, fuse_fill_dir_t filler, off_t, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            if (fb->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            FUSE_STAT st;
            memset(&st, 0, sizeof(st));
            auto actions = [&](const std::string& name, const id_type&, int type) -> bool {
                st.st_mode = FileBase::mode_for_type(type);
                return filler(buffer, name.c_str(), &st, 0) == 0;
            };
            static_cast<Directory*>(fb)->iterate_over_entries(actions);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int create(const char* path, mode_t mode, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFREG;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto fg = internal::create(fs, path, FileBase::REGULAR_FILE, mode, ctx->uid, ctx->gid);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        // bool rdonly = info->flags & O_RDONLY;
        bool rdwr = info->flags & O_RDWR;
        bool wronly = info->flags & O_WRONLY;
        bool append = info->flags & O_APPEND;
        // bool require_read = rdonly | rdwr;
        bool require_write = wronly | append | rdwr;

        try
        {
            if (require_write && internal::is_readonly(ctx))
                return -EROFS;
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            if (info->flags & O_TRUNC)
            {
                fg.get_as<RegularFile>()->truncate(0);
            }
            info->fh = reinterpret_cast<uintptr_t>(fg.release());

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            fb->flush();
            internal::FileGuard fg(&internal::get_fs(ctx)->table, fb);
            fg.reset(nullptr);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int read(const char* path, char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        auto fs = internal::get_fs(ctx);
        fs->logger->log(LoggingLevel::VERBOSE,
                        "%s (path=%s, length=%zu, offset=%lld)",
                        __FUNCTION__,
                        path,
                        len,
                        (long long)off);

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            return static_cast<int>(static_cast<RegularFile*>(fb)->read(buffer, off, len));
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SeriousException& e)
        {
            fs->logger->log(LoggingLevel::ERROR,
                            "%s (path=%s, length=%zu, offset=%lld) encounters %s: %s",
                            __FUNCTION__,
                            path,
                            len,
                            (long long)off,
                            e.type_name(),
                            e.what());
            return -e.error_number();
        }
    }

    int
    write(const char* path, const char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        auto fs = internal::get_fs(ctx);
        fs->logger->log(LoggingLevel::VERBOSE,
                        "%s (path=%s, length=%zu, offset=%lld)",
                        __FUNCTION__,
                        path,
                        len,
                        (long long)off);

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            static_cast<RegularFile*>(fb)->write(buffer, off, len);
            return static_cast<int>(len);
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SeriousException& e)
        {
            fs->logger->log(LoggingLevel::ERROR,

                            "%s (path=%s, length=%zu, offset=%lld) encounters %s: %s",
                            __FUNCTION__,
                            path,
                            len,
                            (long long)off,
                            e.type_name(),
                            e.what());
            return -e.error_number();
        }
    }

    int flush(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            fb->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int truncate(const char* path, off_t size)
    {
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EINVAL;
            fg.get_as<RegularFile>()->truncate(size);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int ftruncate(const char* path, off_t size, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EINVAL;
            static_cast<RegularFile*>(fb)->truncate(size);
            fb->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int unlink(const char* path)
    {
        COMMON_PROLOGUE

        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            internal::remove(fs, path);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int mkdir(const char* path, mode_t mode)
    {
        COMMON_PROLOGUE

        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFDIR;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto fg = internal::create(fs, path, FileBase::DIRECTORY, mode, ctx->uid, ctx->gid);
            if (fg->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int rmdir(const char* path) { return ::securefs::operations::unlink(path); }

    int chmod(const char* path, mode_t mode)
    {
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            auto original_mode = fg->get_mode();
            mode &= 0777;
            mode |= original_mode & S_IFMT;
            fg->set_mode(mode);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int chown(const char* path, uid_t uid, gid_t gid)
    {
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            fg->set_uid(uid);
            fg->set_gid(gid);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int symlink(const char* to, const char* from)
    {
        auto ctx = fuse_get_context();
        auto fs = internal::get_fs(ctx);
        fs->logger->log(LoggingLevel::VERBOSE, "%s (to=%s, from=%s)", __FUNCTION__, to, from);

        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto fg = internal::create(fs, from, FileBase::SYMLINK, S_IFLNK | 0755, ctx->uid, ctx->gid);
            if (fg->type() != FileBase::SYMLINK)
                return -EINVAL;
            fg.get_as<Symlink>()->set(to);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SeriousException& e)
        {
            fs->logger->log(LoggingLevel::ERROR,

                            "%s (to=%s, from=%s) encounters %s: %s",
                            __FUNCTION__,
                            to,
                            from,
                            e.type_name(),
                            e.what());
            return -e.error_number();
        }
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        if (size == 0)
            return -EINVAL;
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::SYMLINK)
                return -EINVAL;
            auto destination = fg.get_as<Symlink>()->get();
            memset(buf, 0, size);
            memcpy(buf, destination.data(), std::min(destination.size(), size - 1));
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int rename(const char* src, const char* dst)
    {
        auto ctx = fuse_get_context();
        auto fs = internal::get_fs(ctx);
        fs->logger->log(LoggingLevel::VERBOSE, "%s (src=%s, dest=%s)", __FUNCTION__, src, dst);

        try
        {
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            id_type src_id, dst_id;
            int src_type, dst_type;

            if (!src_dir->get_entry(src_filename, src_id, src_type))
                return -ENOENT;
            bool dst_exists = (dst_dir->get_entry(dst_filename, dst_id, dst_type));

            if (dst_exists)
            {
                if (src_id == dst_id)
                    return 0;
                if (src_type != FileBase::DIRECTORY && dst_type == FileBase::DIRECTORY)
                    return -EISDIR;
                if (src_type != dst_type)
                    return -EINVAL;
                dst_dir->remove_entry(dst_filename, dst_id, dst_type);
            }
            src_dir->remove_entry(src_filename, src_id, src_type);
            dst_dir->add_entry(dst_filename, src_id, src_type);

            if (dst_exists)
                internal::remove(fs, dst_id, dst_type);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SeriousException& e)
        {
            fs->logger->log(LoggingLevel::ERROR,

                            "%s (src=%s, dest=%s) encounters %s: %s",
                            __FUNCTION__,
                            src,
                            dst,
                            e.type_name(),
                            e.what());
            return -e.error_number();
        }
    }

    int link(const char* src, const char* dst)
    {
        auto ctx = fuse_get_context();
        auto fs = internal::get_fs(ctx);
        fs->logger->log(LoggingLevel::VERBOSE, "%s (src=%s, dest=%s)", __FUNCTION__, src, dst);

        try
        {
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            id_type src_id, dst_id;
            int src_type, dst_type;

            bool src_exists = src_dir->get_entry(src_filename, src_id, src_type);
            if (!src_exists)
                return -ENOENT;
            bool dst_exists = dst_dir->get_entry(dst_filename, dst_id, dst_type);
            if (dst_exists)
                return -EEXIST;

            auto&& table = internal::get_fs(ctx)->table;
            internal::FileGuard guard(&table, table.open_as(src_id, src_type));

            if (guard->type() != FileBase::REGULAR_FILE)
                return -EPERM;

            guard->set_nlink(guard->get_nlink() + 1);
            dst_dir->add_entry(dst_filename, src_id, src_type);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SeriousException& e)
        {
            fs->logger->log(LoggingLevel::ERROR,

                            "%s (src=%s, dest=%s) encounters %s: %s",
                            __FUNCTION__,
                            src,
                            dst,
                            e.type_name(),
                            e.what());
            return -e.error_number();
        }
    }

    int fsync(const char* path, int, struct fuse_file_info* fi)
    {
        COMMON_PROLOGUE

        try
        {
            auto fb = reinterpret_cast<FileBase*>(fi->fh);
            if (!fb)
                return -EINVAL;
            fb->flush();
            fb->fsync();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi)
    {
        return ::securefs::operations::fsync(path, isdatasync, fi);
    }

    int utimens(const char* path, const struct timespec ts[2])
    {
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            fg->utimens(ts);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

#ifdef __APPLE__

    int listxattr(const char* path, char* list, size_t size)
    {
        COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->listxattr(list, size));
        }
        COMMON_CATCH_BLOCK
    }

    static const char* APPLE_FINDER_INFO = "com.apple.FinderInfo";

#define XATTR_COMMON_PROLOGUE                                                                      \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);                                                               \
    fs->logger->log(LoggingLevel::VERBOSE, "%s (path=%s, name=%s)", __FUNCTION__, path, name);

#define XATTR_COMMON_CATCH_BLOCK                                                                   \
    catch (const CommonException& e) { return -e.error_number(); }                                 \
    catch (const SeriousException& e)                                                              \
    {                                                                                              \
        int errc = e.error_number();                                                               \
        if (errc != ENOATTR) /* Attribute not found is very common and normal; no need to log it   \
                                as an error */                                                     \
            fs->logger->log(LoggingLevel::ERROR,                                                   \
                            "%s (path=%s, name=%s) encounters %s: %s",                             \
                            __FUNCTION__,                                                          \
                            path,                                                                  \
                            name,                                                                  \
                            e.type_name(),                                                         \
                            e.what());                                                             \
        return -errc;                                                                              \
    }

    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        XATTR_COMMON_PROLOGUE

        if (position != 0)
            return -EINVAL;

        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->getxattr(name, value, size));
        }
        XATTR_COMMON_CATCH_BLOCK
    }

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position)
    {
        XATTR_COMMON_PROLOGUE

        if (position != 0)
            return -EINVAL;
        if (strcmp(name, "com.apple.quarantine") == 0)
            return 0;    // workaround for the "XXX is damaged" bug on OS X
        if (strcmp(name, APPLE_FINDER_INFO) == 0)
            return -EACCES;

        flags &= XATTR_CREATE | XATTR_REPLACE;
        try
        {
            auto fg = internal::open_all(fs, path);
            fg->setxattr(name, value, size, flags);
            return 0;
        }
        XATTR_COMMON_CATCH_BLOCK
    }

    int removexattr(const char* path, const char* name)
    {
        XATTR_COMMON_PROLOGUE

        try
        {
            auto fg = internal::open_all(fs, path);
            fg->removexattr(name);
            return 0;
        }
        XATTR_COMMON_CATCH_BLOCK
    }
#endif
}
}
