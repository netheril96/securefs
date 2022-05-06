#include "lite_operations.h"
#include "apple_xattr_workaround.h"
#include "fuse_tracer.h"
#include "lite_fs.h"
#include "lite_stream.h"
#include "lock_guard.h"
#include "logger.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"

namespace securefs
{
namespace lite
{
    namespace
    {
        struct BundledContext
        {
            ::securefs::operations::MountOptions* opt;
        };

        FileSystem* get_local_filesystem()
        {
            static thread_local optional<FileSystem> opt_fs;

            auto& local_opt_fs = opt_fs;
            if (local_opt_fs)
                return &(*local_opt_fs);
            auto ctx = static_cast<BundledContext*>(fuse_get_context()->private_data);

            if (ctx->opt->version.value() != 4)
                throwInvalidArgumentException("This function only supports filesystem format 4");

            const auto& master_key = ctx->opt->master_key;

            key_type name_key, content_key, xattr_key, padding_key;
            if (master_key.size() != 3 * KEY_LENGTH && master_key.size() != 4 * KEY_LENGTH)
                throwInvalidArgumentException("Master key has wrong length");

            memcpy(name_key.data(), master_key.data(), KEY_LENGTH);
            memcpy(content_key.data(), master_key.data() + KEY_LENGTH, KEY_LENGTH);
            memcpy(xattr_key.data(), master_key.data() + 2 * KEY_LENGTH, KEY_LENGTH);

            warn_if_key_not_random(name_key, __FILE__, __LINE__);
            warn_if_key_not_random(content_key, __FILE__, __LINE__);
            warn_if_key_not_random(xattr_key, __FILE__, __LINE__);
            if (master_key.size() >= 4 * KEY_LENGTH)
            {
                memcpy(padding_key.data(), master_key.data() + 3 * KEY_LENGTH, KEY_LENGTH);
            }
            if (ctx->opt->max_padding_size > 0)
            {
                warn_if_key_not_random(padding_key, __FILE__, __LINE__);
            }

            TRACE_LOG("\nname_key: %s\ncontent_key: %s\nxattr_key: %s\npadding_key: %s",
                      hexify(name_key).c_str(),
                      hexify(content_key).c_str(),
                      hexify(xattr_key).c_str(),
                      hexify(padding_key).c_str());

            local_opt_fs.emplace(ctx->opt->root,
                                 name_key,
                                 content_key,
                                 xattr_key,
                                 padding_key,
                                 ctx->opt->block_size.value(),
                                 ctx->opt->iv_size.value(),
                                 ctx->opt->max_padding_size,
                                 ctx->opt->flags.value());
            return &(*local_opt_fs);
        }

        void set_file_handle(struct fuse_file_info* info, securefs::lite::Base* base)
        {
            info->fh = reinterpret_cast<uintptr_t>(base);
        }

        Base* get_base_handle(const struct fuse_file_info* info)
        {
            if (!info->fh)
            {
                throwVFSException(EFAULT);
            }
            return reinterpret_cast<Base*>(static_cast<uintptr_t>(info->fh));
        }

        File* get_handle_as_file_checked(const struct fuse_file_info* info)
        {
            auto fp = get_base_handle(info)->as_file();
            if (!fp)
            {
                throwVFSException(EISDIR);
            }
            return fp;
        }

        Directory* get_handle_as_dir_checked(const struct fuse_file_info* info)
        {
            auto fp = get_base_handle(info)->as_dir();
            if (!fp)
            {
                throwVFSException(ENOTDIR);
            }
            return fp;
        }

    }    // namespace
    void* init(struct fuse_conn_info* fsinfo)
    {
        (void)fsinfo;
#ifdef FSP_FUSE_CAP_READDIR_PLUS
        fsinfo->want |= (fsinfo->capable & FSP_FUSE_CAP_READDIR_PLUS);
#endif
        void* args = fuse_get_context()->private_data;
        INFO_LOG("init");
        auto ctx = new BundledContext;
        ctx->opt = static_cast<operations::MountOptions*>(args);
        return ctx;
    }

    void destroy(void*)
    {
        delete static_cast<BundledContext*>(fuse_get_context()->private_data);
        INFO_LOG("destroy");
    }

    int statfs(const char* path, struct fuse_statvfs* buf)
    {
        auto func = [=]()
        {
            if (!buf)
                return -EFAULT;
            auto filesystem = get_local_filesystem();
            filesystem->statvfs(buf);
            // Due to the Base32 encoding and the extra 16 bytes of synthesized IV
            buf->f_namemax = buf->f_namemax * 5 / 8 - 16;
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {buf}});
    }

    int getattr(const char* path, struct fuse_stat* st)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            if (!filesystem->stat(path, st))
                return -ENOENT;

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}});
    }

    int fgetattr(const char* path, struct fuse_stat* st, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto base = get_base_handle(info);
            auto file = base->as_file();
            if (file)
            {
                LockGuard<File> lock_guard(*file, false);
                file->fstat(st);
                return 0;
            }
            auto dir = base->as_dir();
            if (dir)
            {
                auto filesystem = get_local_filesystem();
                if (!filesystem->stat(dir->path(), st))
                    return -ENOENT;
                return 0;
            }
            throwInvalidArgumentException("Neither file nor dir");
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}, {info}});
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            auto traverser = filesystem->opendir(path);
            set_file_handle(info, traverser.release());
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int releasedir(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            delete get_base_handle(info);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int readdir(const char* path,
                void* buf,
                fuse_fill_dir_t filler,
                fuse_off_t off,
                struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fs = get_local_filesystem();
            auto traverser = get_handle_as_dir_checked(info);
            if (!traverser)
                return -EFAULT;
            LockGuard<Directory> lock_guard(*traverser);
            traverser->rewind();
            std::string name;
            struct fuse_stat stbuf;
            memset(&stbuf, 0, sizeof(stbuf));

            while (traverser->next(&name, &stbuf))
            {
#ifndef _WIN32
                if (name == "." || name == "..")
                {
                    continue;
                }
#endif
                int rc =
                    // When random padding is enabled, we cannot obtain accurate size information
                    fs->has_padding() && (stbuf.st_mode & S_IFMT) == S_IFREG
                    ? filler(buf, name.c_str(), nullptr, 0)
                    : filler(buf, name.c_str(), &stbuf, 0);
                if (rc != 0)
                    return -abs(rc);
            }
            return 0;
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {buf}, {(const void*)filler}, {&off}, {info}});
    }

    int create(const char* path, fuse_mode_t mode, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            AutoClosedFile file = filesystem->open(path, O_RDWR | O_CREAT | O_EXCL, mode);
            set_file_handle(info, file.release());
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}, {info}});
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            AutoClosedFile file = filesystem->open(path, info->flags, 0644);
            set_file_handle(info, file.release());
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            delete get_base_handle(info);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int
    read(const char* path, char* buf, size_t size, fuse_off_t offset, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, false);
            return static_cast<int>(fp->read(buf, offset, size));
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buf}, {&size}, {&offset}, {info}});
    }

    int write(const char* path,
              const char* buf,
              size_t size,
              fuse_off_t offset,
              struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->write(buf, offset, size);
            return static_cast<int>(size);
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buf}, {&size}, {&offset}, {info}});
    }

    int flush(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->flush();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    int ftruncate(const char* path, fuse_off_t len, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(len);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&len}, {info}});
    }

    int unlink(const char* path)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->unlink(path);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}});
    }

    int mkdir(const char* path, fuse_mode_t mode)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->mkdir(path, mode);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    int rmdir(const char* path)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->rmdir(path);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}});
    }

    int chmod(const char* path, fuse_mode_t mode)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->chmod(path, mode);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    int chown(const char* path, fuse_uid_t uid, fuse_gid_t gid)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->chown(path, uid, gid);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&uid}, {&gid}});
    }

    int symlink(const char* to, const char* from)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->symlink(to, from);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{to}, {from}});
    }

    int link(const char* src, const char* dest)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->link(src, dest);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{src}, {dest}});
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            (void)filesystem->readlink(path, buf, size);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {(const void*)buf}, {&size}});
    }

    int rename(const char* from, const char* to)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->rename(from, to);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{from}, {to}});
    }

    int fsync(const char* path, int datasync, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->fsync();
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&datasync}, {info}});
    }

    int truncate(const char* path, fuse_off_t len)
    {
        auto func = [=]()
        {
            if (len < 0)
                return -EINVAL;
            auto filesystem = get_local_filesystem();

            AutoClosedFile fp = filesystem->open(path, O_RDWR, 0644);
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(static_cast<size_t>(len));
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&len}});
    }

    int utimens(const char* path, const struct fuse_timespec ts[2])
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->utimens(path, ts);
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
            auto filesystem = get_local_filesystem();
            int rc = static_cast<int>(filesystem->listxattr(path, list, size));
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
            if (position != 0)
                return -EINVAL;
            int rc = precheck_getxattr(&name);
            if (rc <= 0)
                return rc;

            auto filesystem = get_local_filesystem();
            rc = static_cast<int>(filesystem->getxattr(path, name, value, size));
            return rc;
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
            if (position != 0)
                return -EINVAL;
            int rc = precheck_setxattr(&name, &flags);
            if (rc <= 0)
                return rc;
            if (!value || size == 0)
                return 0;

            auto filesystem = get_local_filesystem();
            rc = filesystem->setxattr(path, name, const_cast<char*>(value), size, flags);
            return rc;
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
            int rc = precheck_removexattr(&name);
            if (rc <= 0)
                return rc;
            auto filesystem = get_local_filesystem();
            rc = filesystem->removexattr(path, name);
            return rc;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {name}});
    }
#endif

    void init_fuse_operations(struct fuse_operations* opt, bool xattr)
    {
        memset(opt, 0, sizeof(*opt));

        opt->flag_nopath = true;
        opt->flag_nullpath_ok = true;

        opt->init = &::securefs::lite::init;
        opt->destroy = &::securefs::lite::destroy;
        opt->statfs = &::securefs::lite::statfs;
        opt->getattr = &::securefs::lite::getattr;
        opt->fgetattr = &::securefs::lite::fgetattr;
        opt->opendir = &::securefs::lite::opendir;
        opt->releasedir = &::securefs::lite::releasedir;
        opt->readdir = &::securefs::lite::readdir;
        opt->create = &::securefs::lite::create;
        opt->open = &::securefs::lite::open;
        opt->release = &::securefs::lite::release;
        opt->read = &::securefs::lite::read;
        opt->write = &::securefs::lite::write;
        opt->flush = &::securefs::lite::flush;
        opt->truncate = &::securefs::lite::truncate;
        opt->ftruncate = &::securefs::lite::ftruncate;
        opt->unlink = &::securefs::lite::unlink;
        opt->mkdir = &::securefs::lite::mkdir;
        opt->rmdir = &::securefs::lite::rmdir;
#ifndef _WIN32
        opt->chmod = &::securefs::lite::chmod;
        opt->chown = &::securefs::lite::chown;
        opt->symlink = &::securefs::lite::symlink;
        opt->link = &::securefs::lite::link;
        opt->readlink = &::securefs::lite::readlink;
#endif
        opt->rename = &::securefs::lite::rename;
        opt->fsync = &::securefs::lite::fsync;
        opt->utimens = &::securefs::lite::utimens;

        if (!xattr)
            return;

#ifdef __APPLE__
        opt->listxattr = &::securefs::lite::listxattr;
        opt->getxattr = &::securefs::lite::getxattr;
        opt->setxattr = &::securefs::lite::setxattr;
        opt->removexattr = &::securefs::lite::removexattr;
#endif
    }
}    // namespace lite
}    // namespace securefs
