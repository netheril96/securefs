#include "operations.h"
#include "apple_xattr_workaround.h"
#include "constants.h"
#include "crypto.h"
#include "fuse_tracer.h"
#include "platform.h"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <string>
#include <typeinfo>
#include <utility>

#include <absl/container/inlined_vector.h>
#include <absl/strings/str_split.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

namespace securefs
{
namespace operations
{
    const char* LOCK_FILENAME = ".securefs.lock";

    MountOptions::MountOptions() {}
    MountOptions::~MountOptions() {}

    FileSystemContext::FileSystemContext(const MountOptions& opt)
        : table(opt.version.value(),
                opt.root,
                from_cryptopp_key(opt.master_key),
                opt.flags.value(),
                opt.block_size.value(),
                opt.iv_size.value(),
                opt.max_padding_size)
        , root(opt.root)
        , root_id()
        , flags(opt.flags.value())
        , lock_stream(opt.lock_stream)
    {
        if (opt.version.value() > 3)
            throwInvalidArgumentException("This context object only works with format 1,2,3");
        block_size = opt.block_size.value();
    }

    FileSystemContext::~FileSystemContext()
    {
        if (!lock_stream)
        {
            return;
        }
        lock_stream->close();
        root->remove_file_nothrow(LOCK_FILENAME);
    }
}    // namespace operations
}    // namespace securefs

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
        absl::InlinedVector<std::string, 32> components = absl::StrSplit(
            transform(path, fs->flags & kOptionCaseFoldFileName, fs->flags & kOptionNFCFileName)
                .view(),
            absl::ByChar('/'),
            absl::SkipEmpty());

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
            auto& dir = *result;
            {
                FileLockGuard lg(dir);
                bool exists = dir.cast_as<Directory>()->get_entry(components[i], id, type);
                if (!exists)
                    throwVFSException(ENOENT);
                if (type != FileBase::DIRECTORY)
                    throwVFSException(ENOTDIR);
            }
            result.reset(fs->table.open_as(id, type));
        }
        last_component = components.back();
        return result;
    }

    FileGuard open_all(FileSystemContext* fs, const char* path)
    {
        std::string last_component;
        auto auto_closed_file = open_base_dir(fs, path, last_component);
        if (last_component.empty())
            return auto_closed_file;
        id_type id;
        int type;
        {
            auto& dir = *auto_closed_file;
            FileLockGuard file_lock_guard(dir);
            bool exists = dir.cast_as<Directory>()->get_entry(last_component, id, type);
            if (!exists)
                throwVFSException(ENOENT);
        }
        auto_closed_file.reset(fs->table.open_as(id, type));
        return auto_closed_file;
    }

    // Specialization of `open_all` since `VFSException(ENOENT)` occurs too frequently
    bool open_all(FileSystemContext* fs, const char* path, FileGuard& auto_closed_file)
    {
        std::string last_component;
        auto_closed_file = open_base_dir(fs, path, last_component);
        if (last_component.empty())
            return true;
        id_type id;
        int type;
        {
            auto& dir = *auto_closed_file;
            FileLockGuard file_lock_guard(dir);
            bool exists = dir.cast_as<Directory>()->get_entry(last_component, id, type);
            if (!exists)
            {
                return false;
            }
        }
        auto_closed_file.reset(fs->table.open_as(id, type));
        return true;
    }

    FileGuard create(FileSystemContext* fs,
                     const char* path,
                     int type,
                     uint32_t mode,
                     uint32_t uid,
                     uint32_t gid)
    {
        std::string last_component;
        auto dir = open_base_dir(fs, path, last_component);
        id_type id;
        generate_random(id.data(), id.size());

        FileGuard result(&fs->table, fs->table.create_as(id, type));

        {
            auto& fp = *result;
            FileLockGuard file_lock_guard(fp);
            fp.initialize_empty(mode, uid, gid);
        }

        try
        {
            auto& dirfp = *dir;
            FileLockGuard file_lock_guard(dirfp);
            bool success = dirfp.cast_as<Directory>()->add_entry(last_component, id, type);
            if (!success)
                throwVFSException(EEXIST);
        }
        catch (...)
        {
            auto& fp = *result;
            FileLockGuard file_lock_guard(fp);
            fp.unlink();
            throw;
        }
        return result;
    }

    void remove(FileSystemContext* fs, const id_type& id, int type)
    {
        try
        {
            FileGuard to_be_removed(&fs->table, fs->table.open_as(id, type));
            auto& fp = *to_be_removed;
            FileLockGuard file_lock_guard(fp);
            fp.unlink();
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
            throwVFSException(EPERM);
        id_type id;
        int type;

        {
            FileLockGuard file_lock_guard(*dir);
            if (!dir->get_entry(last_component, id, type))
                throwVFSException(ENOENT);
        }

        FileGuard inner_guard = open_as(fs->table, id, type);
        auto inner_fb = inner_guard.get();
        DoubleFileLockGuard double_file_lock_guard(*dir, *inner_fb);
        if (inner_fb->type() == FileBase::DIRECTORY && !static_cast<Directory*>(inner_fb)->empty())
        {
            std::string contents;
            static_cast<Directory*>(inner_fb)->iterate_over_entries(
                [&contents](const std::string& str, const id_type&, int) -> bool
                {
                    contents.push_back('\n');
                    contents += str;
                    return true;
                });
            WARN_LOG("Trying to remove a non-empty directory \"%s\" with contents: %s",
                     path,
                     contents.c_str());
            throwVFSException(ENOTEMPTY);
        }
        dir->remove_entry(last_component, id, type);
        inner_fb->unlink();
    }

    inline bool is_readonly(struct fuse_context* ctx) { return get_fs(ctx)->table.is_readonly(); }
}    // namespace internal

namespace operations
{
#define COMMON_PROLOGUE                                                                            \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);                                                               \
    (void)fs;                                                                                      \
    OPT_TRACE_WITH_PATH;

    void* init(struct fuse_conn_info* fsinfo)
    {
        (void)fsinfo;
        auto args = static_cast<MountOptions*>(fuse_get_context()->private_data);
        auto fs = new FileSystemContext(*args);
        TRACE_LOG("%s", __FUNCTION__);
        return fs;
    }

    void destroy(void* data)
    {
        auto fs = static_cast<FileSystemContext*>(data);
        TRACE_LOG("%s", __FUNCTION__);
        delete fs;
    }

    int statfs(const char* path, struct fuse_statvfs* fs_info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            fs->table.statfs(fs_info);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {fs_info}});
    }

    int getattr(const char* path, struct fuse_stat* st)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (!st)
                return -EINVAL;

            internal::FileGuard auto_closed_file(nullptr, nullptr);
            if (!internal::open_all(fs, path, auto_closed_file))
                return -ENOENT;
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.stat(st);
            st->st_uid = OSService::getuid();
            st->st_gid = OSService::getgid();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}});
    }

    int fgetattr(const char* path, struct fuse_stat* st, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            FileLockGuard file_lock_guard(*fb);
            fb->stat(st);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}, {info}});
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            if (auto_closed_file->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            info->fh = reinterpret_cast<uintptr_t>(auto_closed_file.release());

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int releasedir(const char* path, struct fuse_file_info* info)
    {
        return ::securefs::operations::release(path, info);
    }

    int readdir(const char* path,
                void* buffer,
                fuse_fill_dir_t filler,
                fuse_off_t off,
                struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            bool has_padding = fs->table.has_padding();
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            if (fb->type() != FileBase::DIRECTORY)
                return -ENOTDIR;

            struct fuse_stat st;
            memset(&st, 0, sizeof(st));

            FileLockGuard file_lock_guard(*fb);
            if (!(fs->flags & kOptionSkipDotDot))
            {
#ifdef _WIN32
                // Only Windows, `st` contains the full information, so we need to call `stat` here.
                fb->stat(&st);
#else
                // On Unix, only information stored in `st` is the file mode. So we do not need to
                // stat "." and "..".
                st.st_mode = S_IFDIR;
                st.st_ino = to_inode_number(fb->get_id());
#endif
                filler(buffer, ".", &st, 0);
                filler(buffer, "..", &st, 0);
            }
            auto actions = [&st, filler, buffer, has_padding](
                               const std::string& name, const id_type& id, int type) -> bool
            {
                st.st_mode = FileBase::mode_for_type(type);
                st.st_ino = to_inode_number(id);
                bool success = filler(buffer,
                                      name.c_str(),
                                      // When random padding is enabled, we cannot obtain accurate
                                      // size information
                                      has_padding && type == FileBase::REGULAR_FILE ? nullptr : &st,
                                      0)
                    == 0;
                if (!success)
                {
                    WARN_LOG("Filling directory buffer failed");
                }
                return success;
            };
            fb->cast_as<Directory>()->iterate_over_entries(actions);
            return 0;
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {buffer}, {(const void*)filler}, {&off}, {info}});
    }

    int create(const char* path, fuse_mode_t mode, struct fuse_file_info* info)
    {
        auto func = [&]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            mode &= ~static_cast<uint32_t>(S_IFMT);
            mode |= S_IFREG;

            if (internal::is_readonly(ctx))
                return -EROFS;
            auto auto_closed_file
                = internal::create(fs, path, FileBase::REGULAR_FILE, mode, ctx->uid, ctx->gid);
            auto_closed_file->cast_as<RegularFile>();
            info->fh = reinterpret_cast<uintptr_t>(auto_closed_file.release());

            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}, {info}});
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            int rdwr = info->flags & O_RDWR;
            int wronly = info->flags & O_WRONLY;
            int append = info->flags & O_APPEND;
            int require_write = wronly | append | rdwr;

            if (require_write && internal::is_readonly(ctx))
                return -EROFS;
            auto auto_closed_file = internal::open_all(fs, path);
            RegularFile* file = auto_closed_file->cast_as<RegularFile>();
            if (info->flags & O_TRUNC)
            {
                FileLockGuard file_lock_guard(*file);
                file->truncate(0);
            }
            info->fh = reinterpret_cast<uintptr_t>(auto_closed_file.release());

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EINVAL;
            {
                FileLockGuard file_lock_guard(*fb);
                fb->flush();
            }
            internal::FileGuard auto_closed_file(&internal::get_fs(ctx)->table, fb);
            auto_closed_file.reset(nullptr);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int
    read(const char* path, char* buffer, size_t len, fuse_off_t off, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            FileLockGuard file_lock_guard(*fb);
            return static_cast<int>(fb->cast_as<RegularFile>()->read(buffer, off, len));
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buffer}, {&len}, {&off}, {info}});
    }

    int write(const char* path,
              const char* buffer,
              size_t len,
              fuse_off_t off,
              struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            FileLockGuard file_lock_guard(*fb);
            fb->cast_as<RegularFile>()->write(buffer, off, len);
            return static_cast<int>(len);
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buffer}, {&len}, {&off}, {info}});
    }

    int flush(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            FileLockGuard file_lock_guard(*fb);
            fb->cast_as<RegularFile>()->flush();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int truncate(const char* path, fuse_off_t size)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.cast_as<RegularFile>()->truncate(size);
            fp.flush();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&size}});
    }

    int ftruncate(const char* path, fuse_off_t size, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            FileLockGuard file_lock_guard(*fb);
            fb->cast_as<RegularFile>()->truncate(size);
            fb->flush();
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&size}, {info}});
    }

    int unlink(const char* path)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (internal::is_readonly(ctx))
                return -EROFS;
            internal::remove(fs, path);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}});
    }

    int mkdir(const char* path, fuse_mode_t mode)
    {
        auto func = [&]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);

            mode &= ~static_cast<uint32_t>(S_IFMT);
            mode |= S_IFDIR;

            if (internal::is_readonly(ctx))
                return -EROFS;
            auto auto_closed_file
                = internal::create(fs, path, FileBase::DIRECTORY, mode, ctx->uid, ctx->gid);
            auto_closed_file->cast_as<Directory>();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    int rmdir(const char* path) { return ::securefs::operations::unlink(path); }

    int chmod(const char* path, fuse_mode_t mode)
    {
        auto func = [&]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            auto original_mode = fp.get_mode();
            mode &= 0777;
            mode |= original_mode & S_IFMT;
            fp.set_mode(mode);
            fp.flush();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    int chown(const char* path, fuse_uid_t uid, fuse_gid_t gid)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);

            fp.set_uid(uid);
            fp.set_gid(gid);
            fp.flush();
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&uid}, {&gid}});
    }

    int symlink(const char* to, const char* from)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);

            if (internal::is_readonly(ctx))
                return -EROFS;
            auto auto_closed_file
                = internal::create(fs, from, FileBase::SYMLINK, S_IFLNK | 0755, ctx->uid, ctx->gid);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.cast_as<Symlink>()->set(to);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{to}, {from}});
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        if (size == 0)
            return -EINVAL;
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            auto destination = fp.cast_as<Symlink>()->get();
            memset(buf, 0, size);
            memcpy(buf, destination.data(), std::min(destination.size(), size - 1));
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {(const void*)buf}, {&size}});
    }

    int rename(const char* src, const char* dst)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            DoubleFileLockGuard double_file_lock_guard(*src_dir, *dst_dir);

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
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{src}, {dst}});
    }

    int link(const char* src, const char* dst)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            std::string src_filename, dst_filename;
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();

            id_type src_id, dst_id;
            int src_type, dst_type;

            DoubleFileLockGuard double_file_lock_guard(*src_dir, *dst_dir);

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

            auto& fp = *guard;
            SpinFileLockGuard sflg(fp);
            fp.set_nlink(fp.get_nlink() + 1);
            dst_dir->add_entry(dst_filename, src_id, src_type);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{src}, {dst}});
    }

    int fsync(const char* path, int dataysnc, struct fuse_file_info* fi)
    {
        auto func = [=]()
        {
            auto fb = reinterpret_cast<FileBase*>(fi->fh);
            if (!fb)
                return -EFAULT;
            FileLockGuard file_lock_guard(*fb);
            fb->flush();
            fb->fsync();
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&dataysnc}, {fi}});
    }

    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi)
    {
        return ::securefs::operations::fsync(path, isdatasync, fi);
    }

    int utimens(const char* path, const struct fuse_timespec ts[2])
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.utimens(ts);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {ts}, {ts ? ts + 1 : ts}});
    }

#ifdef __APPLE__

    int listxattr(const char* path, char* list, size_t size)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            int rc = -1;
            {
                FileLockGuard file_lock_guard(fp);
                rc = static_cast<int>(fp.listxattr(list, size));
            }
            transform_listxattr_result(list, size);
            return rc;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {(const void*)list}, {&size}});
    }

    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        auto func = [&]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (position != 0)
                return -EINVAL;
            int rc = precheck_getxattr(&name);
            if (rc <= 0)
                return rc;

            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            return static_cast<int>(fp.getxattr(name, value, size));
        };
        return FuseTracer::traced_call(
            func,
            FULL_FUNCTION_NAME,
            __LINE__,
            {{path}, {name}, {(const void*)value}, {&size}, {&position}});
    }

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position)
    {
        auto func = [&]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (position != 0)
                return -EINVAL;
            int rc = precheck_setxattr(&name, &flags);
            if (rc <= 0)
                return rc;

            flags &= XATTR_CREATE | XATTR_REPLACE;

            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.setxattr(name, value, size, flags);
            return 0;
        };
        return FuseTracer::traced_call(
            func,
            FULL_FUNCTION_NAME,
            __LINE__,
            {{path}, {name}, {(const void*)value}, {&size}, {&flags}, {&position}});
    }

    int removexattr(const char* path, const char* name)
    {
        auto func = [&]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            int rc = precheck_removexattr(&name);
            if (rc <= 0)
                return rc;

            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.removexattr(name);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {name}});
    }
#endif

    void init_fuse_operations(struct fuse_operations* opt, bool xattr)
    {
        memset(opt, 0, sizeof(*opt));

        opt->flag_nopath = true;
        opt->flag_nullpath_ok = true;
        opt->flag_utime_omit_ok = true;

        opt->getattr = &securefs::operations::getattr;
        opt->fgetattr = &securefs::operations::fgetattr;
        opt->init = &securefs::operations::init;
        opt->destroy = &securefs::operations::destroy;
        opt->opendir = &securefs::operations::opendir;
        opt->releasedir = &securefs::operations::releasedir;
        opt->readdir = &securefs::operations::readdir;
        opt->create = &securefs::operations::create;
        opt->open = &securefs::operations::open;
        opt->read = &securefs::operations::read;
        opt->write = &securefs::operations::write;
        opt->truncate = &securefs::operations::truncate;
        opt->unlink = &securefs::operations::unlink;
        opt->mkdir = &securefs::operations::mkdir;
        opt->rmdir = &securefs::operations::rmdir;
        opt->release = &securefs::operations::release;
        opt->ftruncate = &securefs::operations::ftruncate;
        opt->flush = &securefs::operations::flush;
#ifndef _WIN32
        opt->chmod = &securefs::operations::chmod;
        opt->chown = &securefs::operations::chown;
        opt->symlink = &securefs::operations::symlink;
        opt->link = &securefs::operations::link;
        opt->readlink = &securefs::operations::readlink;
#endif
        opt->rename = &securefs::operations::rename;
        opt->fsync = &securefs::operations::fsync;
        opt->fsyncdir = &securefs::operations::fsyncdir;
        opt->utimens = &securefs::operations::utimens;
        opt->statfs = &securefs::operations::statfs;

        if (!xattr)
            return;
#ifdef __APPLE__
        opt->listxattr = &securefs::operations::listxattr;
        opt->getxattr = &securefs::operations::getxattr;
        opt->setxattr = &securefs::operations::setxattr;
        opt->removexattr = &securefs::operations::removexattr;
#endif
    }
}    // namespace operations
}    // namespace securefs
