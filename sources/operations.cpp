#include "operations.h"

#include <mutex>
#include <algorithm>
#include <utility>
#include <string>
#include <string.h>
#include <typeinfo>

#include <utime.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#else
#include <attr/xattr.h>
#endif

namespace securefs
{
namespace internal
{
    inline operations::FileSystem* get_fs(struct fuse_context* ctx)
    {
        return static_cast<operations::FileSystem*>(ctx->private_data);
    }

    inline Logger* get_logger(struct fuse_context* ctx) { return get_fs(ctx)->logger.get(); }

    class FileGuard
    {
    private:
        FileTable* m_ft;
        FileBase* m_fb;

    public:
        explicit FileGuard(FileTable* ft, FileBase* fb) : m_ft(ft), m_fb(fb) {}

        FileGuard(const FileGuard&) = delete;
        FileGuard& operator=(const FileGuard&) = delete;

        FileGuard(FileGuard&& other) noexcept : m_ft(other.m_ft), m_fb(other.m_fb)
        {
            other.m_ft = nullptr;
            other.m_fb = nullptr;
        }

        FileGuard& operator=(FileGuard&& other) noexcept
        {
            if (this == &other)
                return *this;
            swap(other);
            return *this;
        }

        ~FileGuard()
        {
            try
            {
                reset(nullptr);
            }
            catch (...)
            {
            }
        }

        FileBase* get() noexcept { return m_fb; }
        template <class T>
        T* get_as() noexcept
        {
            return static_cast<T*>(m_fb);
        }
        FileBase& operator*() noexcept { return *m_fb; }
        FileBase* operator->() noexcept { return m_fb; }
        FileBase* release() noexcept
        {
            auto rt = m_fb;
            m_fb = nullptr;
            return rt;
        }
        void reset(FileBase* fb)
        {
            if (m_ft && m_fb)
            {
                std::lock_guard<FileTable> lg(*m_ft);
                m_ft->close(m_fb);
            }
            m_fb = fb;
        }
        void swap(FileGuard& other) noexcept
        {
            std::swap(m_ft, other.m_ft);
            std::swap(m_fb, other.m_fb);
        }
    };

    FileBase* table_open_as(FileTable& t, const id_type& id, int type)
    {
        std::lock_guard<FileTable> lg(t);
        return t.open_as(id, type);
    }

    FileBase* table_create_as(FileTable& t, const id_type& id, int type)
    {
        std::lock_guard<FileTable> lg(t);
        return t.create_as(id, type);
    }

    bool dir_get_entry(Directory* dir, const std::string& name, id_type& id, int& type)
    {
        assert(dir);
        std::lock_guard<FileBase> lg(*dir);
        return dir->get_entry(name, id, type);
    }

    bool dir_add_entry(Directory* dir, const std::string& name, const id_type& id, int type)
    {
        assert(dir);
        std::lock_guard<FileBase> lg(*dir);
        bool result = dir->add_entry(name, id, type);
        return result;
    }

    FileGuard
    open_base_dir(struct fuse_context* ctx, const std::string& path, std::string& last_component)
    {
        assert(ctx);
        auto components = split(path, '/');
        auto fs = get_fs(ctx);
        FileGuard result(&fs->table, table_open_as(fs->table, fs->root_id, FileBase::DIRECTORY));
        if (components.empty())
        {
            last_component = std::string();
            return result;
        }
        id_type id;
        int type;

        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            bool exists = dir_get_entry(result.get_as<Directory>(), components[i], id, type);
            if (!exists)
                throw OSException(ENOENT);
            if (type != FileBase::DIRECTORY)
                throw OSException(ENOTDIR);
            result.reset(table_open_as(fs->table, id, type));
        }
        last_component = components.back();
        return result;
    }

    FileGuard open_all(struct fuse_context* ctx, const std::string& path)
    {
        auto fs = get_fs(ctx);
        std::string last_component;
        auto fg = open_base_dir(ctx, path, last_component);
        if (last_component.empty())
            return fg;
        id_type id;
        int type;
        bool exists = dir_get_entry(fg.get_as<Directory>(), last_component, id, type);
        if (!exists)
            throw OSException(ENOENT);
        fg.reset(table_open_as(fs->table, id, type));
        return fg;
    }

    template <class Initializer>
    FileGuard
    create(struct fuse_context* ctx, const std::string& path, int type, const Initializer& init)
    {
        auto fs = get_fs(ctx);
        std::string last_component;
        auto dir = open_base_dir(ctx, path, last_component);
        id_type id;
        generate_random(id.data(), id.size());

        FileGuard result(&fs->table, table_create_as(fs->table, id, type));
        {
            std::lock_guard<FileBase> lg(*result);
            init(result.get());
        }

        try
        {
            bool success = dir_add_entry(dir.get_as<Directory>(), last_component, id, type);
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

    void remove(struct fuse_context* ctx, const id_type& id, int type)
    {
        try
        {
            auto fs = get_fs(ctx);
            FileGuard to_be_removed(&fs->table, table_open_as(fs->table, id, type));
            std::lock_guard<FileBase> guard(*to_be_removed);
            to_be_removed->unlink();
        }
        catch (...)
        {
            // Errors in unlinking the actual underlying file can be ignored
            // They will not affect the apparent filesystem operations
        }
    }

    void remove(struct fuse_context* ctx, const std::string& path)
    {
        std::string last_component;
        auto dir = open_base_dir(ctx, path, last_component);
        if (last_component.empty())
            throw OSException(EPERM);
        id_type id;
        int type;
        {
            std::lock_guard<FileBase> guard(*dir);
            if (!dir.get_as<Directory>()->remove_entry(last_component, id, type))
                throw OSException(ENOENT);
        }
        remove(ctx, id, type);
    }

    inline bool is_readonly(struct fuse_context* ctx) { return get_fs(ctx)->table.is_readonly(); }

    int log_error(struct fuse_context* ctx,
                  const ExceptionBase& e,
                  const char* func,
                  const char* file,
                  int line)
    {
        auto logger = get_logger(ctx);
        if (logger && e.level() >= logger->get_level())
            logger->log(
                e.level(), fmt::format("{}: {}", e.type_name(), e.message()), func, file, line);
        return -e.error_number();
    }

    int log_general_error(struct fuse_context* ctx,
                          const std::exception& e,
                          const char* func,
                          const char* file,
                          int line)
    {
        auto logger = get_logger(ctx);
        if (logger && LoggingLevel::ERROR >= logger->get_level())
            logger->log(LoggingLevel::ERROR,
                        fmt::format("An unexcepted exception of type {} occurrs: {}",
                                    typeid(e).name(),
                                    e.what()),
                        func,
                        file,
                        line);
        return -EPERM;
    }
}

namespace operations
{

#define COMMON_CATCH_BLOCK                                                                         \
    catch (const OSException& e) { return -e.error_number(); }                                     \
    catch (const ExceptionBase& e)                                                                 \
    {                                                                                              \
        return internal::log_error(ctx, e, __PRETTY_FUNCTION__, __FILE__, __LINE__);               \
    }                                                                                              \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        return internal::log_general_error(ctx, e, __PRETTY_FUNCTION__, __FILE__, __LINE__);       \
    }

    int getattr(const char* path, struct stat* st)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
            fg->stat(st);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
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

    int
    readdir(const char*, void* buffer, fuse_fill_dir_t filler, off_t, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            struct stat st;
            memset(&st, 0, sizeof(st));
            auto actions = [&](const std::string& name, const id_type&, int type) -> bool
            {
                st.st_mode = FileBase::mode_for_type(type);
                return filler(buffer, name.c_str(), &st, 0) == 0;
            };
            std::lock_guard<FileBase> lg(*fb);
            static_cast<Directory*>(fb)->iterate_over_entries(actions);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int create(const char* path, mode_t mode, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFREG;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_file = [=](FileBase* fb)
            {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(mode);
            };
            auto fg = internal::create(ctx, path, FileBase::REGULAR_FILE, init_file);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            info->fh = reinterpret_cast<uintptr_t>(fg.release());
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
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
            auto fg = internal::open_all(ctx, path);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            if (info->flags & O_TRUNC)
            {
                std::lock_guard<FileBase> lg(*fg);
                fg.get_as<RegularFile>()->truncate(0);
            }
            info->fh = reinterpret_cast<uintptr_t>(fg.release());
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int release(const char*, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            {
                std::lock_guard<FileBase> lg(*fb);
                fb->flush();
            }
            internal::FileGuard fg(&internal::get_fs(ctx)->table, fb);
            fg.reset(nullptr);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int read(const char*, char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            std::lock_guard<FileBase> lg(*fb);
            return static_cast<int>(static_cast<RegularFile*>(fb)->read(buffer, off, len));
        }
        COMMON_CATCH_BLOCK
    }

    int write(const char*, const char* buffer, size_t len, off_t off, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            std::lock_guard<FileBase> lg(*fb);
            static_cast<RegularFile*>(fb)->write(buffer, off, len);
            return static_cast<int>(len);
        }
        COMMON_CATCH_BLOCK
    }

    int flush(const char*, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EPERM;
            std::lock_guard<FileBase> lg(*fb);
            fb->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int truncate(const char* path, off_t size)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            if (fg->type() != FileBase::REGULAR_FILE)
                return -EINVAL;
            std::lock_guard<FileBase> lg(*fg);
            fg.get_as<RegularFile>()->truncate(size);
            fg->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int ftruncate(const char*, off_t size, struct fuse_file_info* info)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            if (fb->type() != FileBase::REGULAR_FILE)
                return -EINVAL;
            std::lock_guard<FileBase> lg(*fb);
            static_cast<RegularFile*>(fb)->truncate(size);
            fb->flush();
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int unlink(const char* path)
    {
        auto ctx = fuse_get_context();
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            internal::remove(ctx, path);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int mkdir(const char* path, mode_t mode)
    {
        auto ctx = fuse_get_context();
        mode &= ~static_cast<uint32_t>(S_IFMT);
        mode |= S_IFDIR;
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_dir = [=](FileBase* fb)
            {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(mode);
            };
            auto fg = internal::create(ctx, path, FileBase::DIRECTORY, init_dir);
            if (fg->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int rmdir(const char* path) { return ::securefs::operations::unlink(path); }

    int chmod(const char* path, mode_t mode)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
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
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
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
        try
        {
            if (internal::is_readonly(ctx))
                return -EROFS;
            auto init_symlink = [=](FileBase* fb)
            {
                fb->set_uid(ctx->uid);
                fb->set_gid(ctx->gid);
                fb->set_nlink(1);
                fb->set_mode(S_IFLNK | 0755);
                static_cast<Symlink*>(fb)->set(to);
            };
            auto fg = internal::create(ctx, from, FileBase::SYMLINK, init_symlink);
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
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            if (fg->type() != FileBase::SYMLINK)
                return -EINVAL;
            std::lock_guard<FileBase> lg(*fg);
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
        try
        {
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(ctx, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(ctx, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            id_type src_id, dst_id;
            int src_type, dst_type;
            bool src_exists, dst_exists;

            auto move_entries = [&]() -> void
            {
                // The order of operation is very important.
                //
                // When any of this fail, we'd rather let the directory entries vanish than have two
                // directory entries pointing to the same file without incrementing the nlink field.
                // The unreferenced file can still be recovered, but dubious reference may get the
                // actual file deleted when the user tries to remove one of the wrong entry.
                //
                // Incrementing and decrementing nlink for the source file will make synchronization
                // tricky, because then there will be three locking operations interleaving, which
                // may lead to deadlock or livelock.
                src_exists = src_dir->get_entry(src_filename, src_id, src_type);
                if (!src_exists)
                    return;
                dst_exists = dst_dir->get_entry(dst_filename, dst_id, dst_type);
                if (memcmp(src_id.data(), dst_id.data(), ID_LENGTH) == 0)
                    return;
                if (dst_exists)
                    dst_dir->remove_entry(dst_filename, dst_id, dst_type);
                src_dir->remove_entry(src_filename, src_id, src_type);
                dst_dir->add_entry(dst_filename, src_id, src_type);
            };

            // For templates greater, less, greater_equal, and less_equal, the specializations for
            // any pointer type yield a total order, even if the built-in operators <, >, <=, >= do
            // not.
            std::less<Directory*> comparator;

            // We use the order of pointers to enforce the order of locking so that deadlock
            // cannot occur
            if (comparator(src_dir, dst_dir))
            {
                std::lock_guard<FileBase> lg1(*src_dir);
                std::lock_guard<FileBase> lg2(*dst_dir);
                move_entries();
            }
            else if (comparator(dst_dir, src_dir))
            {
                std::lock_guard<FileBase> lg1(*dst_dir);
                std::lock_guard<FileBase> lg2(*src_dir);
                move_entries();
            }
            else
            {
                std::lock_guard<FileBase> lg1(*dst_dir);
                move_entries();
            }

            if (!src_exists)
                return -ENOENT;

            if (dst_exists)
            {
                internal::remove(ctx, dst_id, dst_type);
            }

            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int fsync(const char*, int, struct fuse_file_info* fi)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fb = reinterpret_cast<FileBase*>(fi->fh);
            if (!fb)
                return -EINVAL;
            std::lock_guard<FileBase> lg(*fb);
            int fd = fb->file_descriptor();
            int rc = ::fsync(fd);
            if (rc < 0)
                return -errno;
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
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            int rc = 0;
            std::lock_guard<FileBase> lg(*fg);
            int fd = fg->file_descriptor();

#if _XOPEN_SOURCE >= 700 || _POSIX_C_SOURCE >= 200809L
            rc = ::futimens(fd, ts);
#else
            if (!ts)
                rc = ::futimes(fd, nullptr);
            else
            {
                struct timeval time_values[2];
                for (size_t i = 0; i < 2; ++i)
                {
                    time_values[i].tv_sec = ts[i].tv_sec;
                    time_values[i].tv_usec
                        = static_cast<decltype(time_values[i].tv_usec)>(ts[i].tv_nsec / 1000);
                }
                rc = ::futimes(fd, time_values);
            }
#endif
            if (rc < 0)
                return -errno;
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

    int listxattr(const char* path, char* list, size_t size)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
            return static_cast<int>(fg->listxattr(list, size));
        }
        COMMON_CATCH_BLOCK
    }

#ifdef __APPLE__
    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        if (position != 0)
            return -EINVAL;
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
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
        if (position != 0)
            return -EINVAL;
        if (strcmp(name, "com.apple.quarantine") == 0)
            return 0;    // workaround for the "XXX is damaged" bug on OS X
        if (strcmp(name, "com.apple.FinderInfo") == 0)
            return -EACCES;    // FinderInfo cannot be encrypted, because its format and length is
                               // artificially restricted

        auto ctx = fuse_get_context();
        flags &= XATTR_CREATE | XATTR_REPLACE;
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
            fg->setxattr(name, value, size, flags);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }

#else
    int getxattr(const char* path, const char* name, char* value, size_t size)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
            return static_cast<int>(fg->getxattr(name, value, size));
        }
        COMMON_CATCH_BLOCK
    }

    int setxattr(const char* path, const char* name, const char* value, size_t size, int flags)
    {
        auto ctx = fuse_get_context();
        flags &= XATTR_CREATE | XATTR_REPLACE;
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
            fg->setxattr(name, value, size, flags);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }
#endif

    int removexattr(const char* path, const char* name)
    {
        auto ctx = fuse_get_context();
        try
        {
            auto fg = internal::open_all(ctx, path);
            std::lock_guard<FileBase> lg(*fg);
            fg->removexattr(name);
            return 0;
        }
        COMMON_CATCH_BLOCK
    }
}
}
