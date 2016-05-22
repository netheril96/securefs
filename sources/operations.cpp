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

using securefs::operations::FileSystem;

namespace securefs
{
namespace internal
{
    inline FileSystem* get_fs(struct fuse_context* ctx)
    {
        return static_cast<FileSystem*>(ctx->private_data);
    }

    typedef AutoClosedFileBase FileGuard;

    FileGuard open_base_dir(FileSystem* fs, const std::string& path, std::string& last_component)
    {

#ifdef _WIN32
        auto components = split(to_lower(path), '/');    // Stupid WIN32 API messes up cases
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

    FileGuard open_all(FileSystem* fs, const std::string& path)
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
    bool open_all(FileSystem* fs, const std::string& path, FileGuard& fg)
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

    template <class Initializer>
    FileGuard create(FileSystem* fs, const std::string& path, int type, const Initializer& init)
    {
        std::string last_component;
        auto dir = open_base_dir(fs, path, last_component);
        id_type id;
        generate_random(id.data(), id.size());

        FileGuard result(&fs->table, fs->table.create_as(id, type));
        init(result.get());

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

    void remove(FileSystem* fs, const id_type& id, int type)
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

    void remove(FileSystem* fs, const std::string& path)
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

    int log_error(FileSystem* fs, const ExceptionBase& e, const char* func)
    {
        auto logger = fs->logger.get();
        if (logger && e.level() >= logger->get_level())
            logger->log(e.level(), fmt::format("{}: {}", e.type_name(), e.message()), func);
        return -e.error_number();
    }

    int log_general_error(FileSystem* fs, const std::exception& e, const char* func)
    {
        auto logger = fs->logger.get();
        if (logger && LoggingLevel::Error >= logger->get_level())
            logger->log(LoggingLevel::Error,
                        fmt::format("An unexcepted exception of type {} occurred: {}",
                                    typeid(e).name(),
                                    e.what()),
                        func);
        return -EPERM;
    }
}

namespace operations
{

    FileSystem::FileSystem(const FSOptions& opt)
        : table(opt.version.get(),
                opt.root,
                opt.master_key.get(),
                opt.flags.get(),
                opt.block_size.get(),
                opt.iv_size.get())
        , root_id()
        , logger(opt.logger)
    {
        block_size = opt.block_size.get();
    }

    FileSystem::~FileSystem() {}

#define COMMON_CATCH_BLOCK                                                                         \
    catch (const OSException& e) { return -e.error_number(); }                                     \
    catch (const ExceptionBase& e) { return internal::log_error(fs, e, __PRETTY_FUNCTION__); }     \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        return internal::log_general_error(fs, e, __PRETTY_FUNCTION__);                            \
    }

#ifdef _WIN32
    static std::mutex global_mutex;    // Stupid Dokany does not respect the "single threaded" flag
#define COMMON_PROLOGUE                                                                            \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);                                                               \
    std::lock_guard<std::mutex> global_guard(global_mutex);
#else
#define COMMON_PROLOGUE                                                                            \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);
#endif

#define DEBUG_LOG(msg)                                                                             \
    if (fs->logger && fs->logger->get_level() <= LoggingLevel::Debug)                              \
    fs->logger->log(LoggingLevel::Debug, msg, __PRETTY_FUNCTION__)

    void* init(struct fuse_conn_info*)
    {
        auto args = static_cast<FSOptions*>(fuse_get_context()->private_data);
        auto fs = new FileSystem(*args);
        DEBUG_LOG("init");
        fputs("Filesystem mounted successfully\n", stderr);
        return fs;
    }

    void destroy(void* data)
    {
        auto fs = static_cast<FileSystem*>(data);
        DEBUG_LOG("destroy");
        delete fs;
        fputs("Filesystem unmounted successfully\n", stderr);
    }

    int statfs(const char* path, struct statvfs* fs_info)
    {
        COMMON_PROLOGUE
        DEBUG_LOG(fmt::format("path={}", path));
        try
        {
            fs->table.statfs(fs_info);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int getattr(const char* path, real_stat_type* st)
    {
        COMMON_PROLOGUE
        DEBUG_LOG(fmt::format("path={}", path));

        try
        {
            if (!st)
                return -EINVAL;

            internal::FileGuard fg(nullptr, nullptr);
            if (!internal::open_all(fs, path, fg))
                return -ENOENT;

            fg->stat(st);

#ifdef _WIN32
            st->st_mode |= 0666;    // The permission system on Windows are just insane, so we just
                                    // permit everything
#endif

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        DEBUG_LOG(fmt::format("path={}", path));

        try
        {
            auto fg = internal::open_all(fs, path);
            if (fg->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());

            DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, info->fh));

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
        DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, info->fh));

        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            real_stat_type st;
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

        DEBUG_LOG(fmt::format("path={}", path));

        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFREG;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_file = [=](FileBase* fb) {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(mode);
            };
            auto fg = internal::create(fs, path, FileBase::REGULAR_FILE, init_file);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());

            DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, info->fh));

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={}", path));

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

            DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, info->fh));

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE
        DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, info->fh));

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
        COMMON_PROLOGUE

        DEBUG_LOG(
            fmt::format("path={} handle=0x{:x} length={} offset={}", path, info->fh, len, off));
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            return static_cast<int>(static_cast<RegularFile*>(fb)->read(buffer, off, len));
        }
        COMMON_CATCH_BLOCK
    }

    int
    write(const char* path, const char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(
            fmt::format("path={} handle=0x{:x} length={} offset={}", path, info->fh, len, off));

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
        COMMON_CATCH_BLOCK
    }

    int flush(const char* path, struct fuse_file_info* info)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, info->fh));

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

        DEBUG_LOG(fmt::format("path={} size={}", path, size));
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

        DEBUG_LOG(fmt::format("path={} size={} handle=0x{:x}", path, size, info->fh));
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

        DEBUG_LOG(fmt::format("path={}", path));

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

        DEBUG_LOG(fmt::format("path={} mode={}", path, mode));

        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFDIR;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_dir = [=](FileBase* fb) {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(mode);
            };
            auto fg = internal::create(fs, path, FileBase::DIRECTORY, init_dir);
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

        DEBUG_LOG(fmt::format("path={} mode={}", path, mode));

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

        DEBUG_LOG(fmt::format("path={} uid={} gid={}", path, uid, gid));

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
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("to={} from={}", to, from));

        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_symlink = [=](FileBase* fb) {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(S_IFLNK | 0755);
                static_cast<Symlink*>(fb)->set(to);
            };
            auto fg = internal::create(fs, from, FileBase::SYMLINK, init_symlink);
            if (fg->type() != FileBase::SYMLINK)
                return -EINVAL;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        if (size == 0)
            return -EINVAL;
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={}", path));

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
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("src={} dst={}", src, dst));

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
        COMMON_CATCH_BLOCK
    }

    int link(const char* src, const char* dst)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("src={} dst={}", src, dst));

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
        COMMON_CATCH_BLOCK
    }

    int fsync(const char* path, int, struct fuse_file_info* fi)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={} handle=0x{:x}", path, fi->fh));

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

        if (ts)
        {
            DEBUG_LOG(fmt::format("path={} access_time={}({}) modification_time={}({})",
                                  path,
                                  ts[0].tv_sec,
                                  ts[0].tv_nsec,
                                  ts[1].tv_sec,
                                  ts[1].tv_nsec));
        }
        else
        {
            DEBUG_LOG(fmt::format("path={} time=current", path));
        }

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

        DEBUG_LOG(fmt::format("path={}", path));

        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->listxattr(list, size));
        }
        COMMON_CATCH_BLOCK
    }

    static const char* APPLE_FINDER_INFO = "com.apple.FinderInfo";

    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={} name={}", path, name));

        if (position != 0)
            return -EINVAL;

        try
        {
            auto fg = internal::open_all(fs, path);
            return static_cast<int>(fg->getxattr(name, value, size));
        }
        COMMON_CATCH_BLOCK
    }

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={} name={} value={}", path, name, std::string(value, size)));

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
        COMMON_CATCH_BLOCK
    }

    int removexattr(const char* path, const char* name)
    {
        COMMON_PROLOGUE

        DEBUG_LOG(fmt::format("path={} name={}", path, name));

        try
        {
            auto fg = internal::open_all(fs, path);
            fg->removexattr(name);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

#endif
}
}
