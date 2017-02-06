#include "lite_operations.h"
#include "lite_fs.h"
#include "lite_stream.h"
#include "logger.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"

#ifndef HAS_THREAD_LOCAL
#include <pthread.h>
#endif

#include <math.h>

namespace securefs
{
namespace lite
{
    namespace
    {
        FileSystem* get_local_filesystem(void)
        {
#ifdef HAS_THREAD_LOCAL
            thread_local FileSystem local_fs(
                *static_cast<const FileSystemOptions*>(fuse_get_context()->private_data));
            return &local_fs;
#else
            struct FileSystemKey
            {
                pthread_key_t key;

                FileSystemKey()
                {
                    int rc = pthread_key_create(
                        &key, [](void* ptr) { delete static_cast<FileSystem*>(ptr); });
                    if (rc != 0)
                        THROW_POSIX_EXCEPTION(rc, "pthread_key_create");
                }
                ~FileSystemKey() { pthread_key_delete(key); }
            };

            static FileSystemKey fskey;

            auto result = static_cast<FileSystem*>(pthread_getspecific(fskey.key));
            if (!result)
            {
                result = new FileSystem(
                    *static_cast<const FileSystemOptions*>(fuse_get_context()->private_data));
                pthread_setspecific(fskey.key, result);
            }
            return result;
#endif
        }
    }

#define SINGLE_COMMON_PROLOGUE                                                                     \
    auto filesystem = get_local_filesystem();                                                      \
    OPT_TRACE_WITH_PATH;

#define SINGLE_COMMON_EPILOGUE OPT_CATCH_WITH_PATH

    void* init(struct fuse_conn_info*)
    {
        auto args = fuse_get_context()->private_data;
        global_logger->info("init");
        return args;
    }

    void destroy(void*) { global_logger->info("destroy"); }

    int statfs(const char* path, struct fuse_statvfs* buf)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            if (!buf)
                return -EFAULT;
            filesystem->statvfs(buf);
            // Due to the Base32 encoding and the extra 16 bytes of synthesized IV
            buf->f_namemax = buf->f_namemax * 5 / 8 - 16;
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int getattr(const char* path, struct fuse_stat* st)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            if (!filesystem->stat(path, st))
                return -ENOENT;
            global_logger->trace("stat (%s): mode=0%o, uid=%u, gid=%u, size=%zu",
                                 path,
                                 st->st_mode,
                                 (unsigned)st->st_uid,
                                 (unsigned)st->st_gid,
                                 (size_t)st->st_size);
            if (is_windows())
                st->st_mode |= 0777;
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            auto traverser = filesystem->create_traverser(path);
            info->fh = reinterpret_cast<uintptr_t>(traverser.release());
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int releasedir(const char* path, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s", __func__, path);
        try
        {
            delete reinterpret_cast<DirectoryTraverser*>(info->fh);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int readdir(const char* path,
                void* buf,
                fuse_fill_dir_t filler,
                fuse_off_t,
                struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            auto traverser = reinterpret_cast<DirectoryTraverser*>(info->fh);
            std::unique_ptr<DirectoryTraverser> guard;
            if (!traverser)
            {
                // Bug in WinFsp
                // Open it ourselves
                guard = filesystem->create_traverser(path);
                traverser = guard.get();
            }
            std::string name;
            fuse_mode_t mode;
            struct fuse_stat stbuf;
            memset(&stbuf, 0, sizeof(stbuf));

#ifdef WIN32
            filler(buf, ".", nullptr, 0);
            filler(buf, "..", nullptr, 0);
#endif

            while (traverser->next(&name, &mode))
            {
                stbuf.st_mode = mode;
                int rc = filler(buf, name.c_str(), mode ? &stbuf : nullptr, 0);
                if (rc != 0)
                    return -abs(rc);
            }
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int create(const char* path, fuse_mode_t mode, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            AutoClosedFile file = filesystem->open(path, O_RDWR | O_CREAT | O_EXCL, mode);
            info->fh = reinterpret_cast<uintptr_t>(file.release());
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            AutoClosedFile file = filesystem->open(path, info->flags, 0644);
            info->fh = reinterpret_cast<uintptr_t>(file.release());
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s", __func__, path);
        try
        {
            delete reinterpret_cast<File*>(info->fh);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int
    read(const char* path, char* buf, size_t size, fuse_off_t offset, struct fuse_file_info* info)
    {
        OPT_TRACE_WITH_PATH_OFF_LEN(offset, size);
        auto fp = reinterpret_cast<File*>(info->fh);
        if (!fp)
            return -EFAULT;

        try
        {
            fp->lock(false);
            DEFER(fp->unlock());
            return static_cast<int>(fp->read(buf, offset, size));
        }
        OPT_CATCH_WITH_PATH_OFF_LEN(offset, size)
    }

    int write(const char* path,
              const char* buf,
              size_t size,
              fuse_off_t offset,
              struct fuse_file_info* info)
    {
        OPT_TRACE_WITH_PATH_OFF_LEN(offset, size);
        auto fp = reinterpret_cast<File*>(info->fh);
        if (!fp)
            return -EFAULT;

        try
        {
            fp->lock(true);
            DEFER(fp->unlock());
            fp->write(buf, offset, size);
            return static_cast<int>(size);
        }
        OPT_CATCH_WITH_PATH_OFF_LEN(offset, size)
    }

    int flush(const char* path, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s", __func__, path);
        auto fp = reinterpret_cast<File*>(info->fh);
        if (!fp)
            return -EFAULT;

        try
        {
            fp->lock(true);
            DEFER(fp->unlock());
            fp->flush();
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int ftruncate(const char* path, fuse_off_t len, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s with length=%lld", __func__, path, static_cast<long long>(len));
        auto fp = reinterpret_cast<File*>(info->fh);
        if (!fp)
            return -EFAULT;

        try
        {
            fp->lock(true);
            DEFER(fp->unlock());
            fp->resize(len);
            return 0;
        }
        catch (const std::exception& e)
        {
            auto ebase = dynamic_cast<const ExceptionBase*>(&e);
            auto code = ebase ? ebase->error_number() : EPERM;
            auto type_name = ebase ? ebase->type_name() : typeid(e).name();
            global_logger->error("%s %s (length=%lld) encounters exception %s (code=%d): %s",
                                 __func__,
                                 path,
                                 static_cast<long long>(len),
                                 type_name,
                                 code,
                                 e.what());
            return -code;
        }
    }

    int unlink(const char* path)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            filesystem->unlink(path);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int mkdir(const char* path, fuse_mode_t mode)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            filesystem->mkdir(path, mode);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int rmdir(const char* path)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            filesystem->rmdir(path);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int chmod(const char* path, fuse_mode_t mode)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            filesystem->chmod(path, mode);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int symlink(const char* to, const char* from)
    {
        auto filesystem = get_local_filesystem();
        OPT_TRACE_WITH_TWO_PATHS(to, from);

        try
        {
            filesystem->symlink(to, from);
            return 0;
        }
        OPT_CATCH_WITH_TWO_PATHS(to, from)
    }

    int link(const char* src, const char* dest)
    {
        auto filesystem = get_local_filesystem();
        OPT_TRACE_WITH_TWO_PATHS(src, dest);

        try
        {
            filesystem->link(src, dest);
            return 0;
        }
        OPT_CATCH_WITH_TWO_PATHS(src, dest)
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            (void)filesystem->readlink(path, buf, size);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int rename(const char* from, const char* to)
    {
        auto filesystem = get_local_filesystem();
        OPT_TRACE_WITH_TWO_PATHS(from, to);

        try
        {
            filesystem->rename(from, to);
            return 0;
        }
        OPT_CATCH_WITH_TWO_PATHS(from, to)
    }

    int fsync(const char* path, int, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s", __func__, path);
        auto fp = reinterpret_cast<File*>(info->fh);
        if (!fp)
            return -EFAULT;

        try
        {
            fp->lock(true);
            DEFER(fp->unlock());
            fp->fsync();
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int truncate(const char* path, fuse_off_t len)
    {
        if (len < 0)
            return -EINVAL;

        global_logger->trace("%s %s (len=%lld)", __func__, path, static_cast<long long>(len));
        auto filesystem = get_local_filesystem();

        try
        {
            AutoClosedFile fp = filesystem->open(path, O_RDWR, 0644);
            fp->lock(true);
            DEFER(fp->unlock());
            fp->resize(static_cast<size_t>(len));
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

    int utimens(const char* path, const struct fuse_timespec ts[2])
    {
        SINGLE_COMMON_PROLOGUE
        try
        {
            filesystem->utimens(path, ts);
            return 0;
        }
        SINGLE_COMMON_EPILOGUE
    }

#ifdef __APPLE__
    int listxattr(const char* path, char* list, size_t size)
    {
        auto filesystem = get_local_filesystem();
        return static_cast<int>(filesystem->listxattr(path, list, size));
    }

    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        if (position != 0)
            return -EINVAL;
        if (strcmp(name, "com.apple.quarantine") == 0)
            return -ENOATTR;    // workaround for the "XXX is damaged" bug on OS X
        if (strcmp(name, "com.apple.FinderInfo") == 0)
            return -ENOATTR;    // stupid Apple hardcodes the size of xattr values

        auto filesystem = get_local_filesystem();
        return static_cast<int>(filesystem->getxattr(path, name, value, size));
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
            return -EACCES;    // stupid Apple hardcodes the size of xattr values
        if (!value || size == 0)
            return 0;

        auto filesystem = get_local_filesystem();
        return filesystem->setxattr(path, name, const_cast<char*>(value), size, flags);
    }
    int removexattr(const char* path, const char* name)
    {
        auto filesystem = get_local_filesystem();
        return filesystem->removexattr(path, name);
    }
#endif

    void init_fuse_operations(fuse_operations* opt, const std::string& data_dir, bool noxattr)
    {
        (void)data_dir;

        memset(opt, 0, sizeof(*opt));

        opt->init = &::securefs::lite::init;
        opt->destroy = &::securefs::lite::destroy;
        opt->statfs = &::securefs::lite::statfs;
        opt->getattr = &::securefs::lite::getattr;
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
        opt->chmod = &::securefs::lite::chmod;
        opt->symlink = &::securefs::lite::symlink;
        opt->link = &::securefs::lite::link;
        opt->readlink = &::securefs::lite::readlink;
        opt->rename = &::securefs::lite::rename;
        opt->fsync = &::securefs::lite::fsync;
        opt->utimens = &::securefs::lite::utimens;

        if (noxattr)
            return;

#ifdef __APPLE__
        auto rc = OSService::get_default().listxattr(data_dir.c_str(), nullptr, 0);
        if (rc < 0)
        {
            global_logger->warn("Underlying directory %s does not support extended attribute (%s)",
                                data_dir.c_str(),
                                sane_strerror(-static_cast<int>(rc)).c_str());
            return;
        }

        opt->listxattr = &::securefs::lite::listxattr;
        opt->getxattr = &::securefs::lite::getxattr;
        opt->setxattr = &::securefs::lite::setxattr;
        opt->removexattr = &::securefs::lite::removexattr;

#endif
    }
}
}
