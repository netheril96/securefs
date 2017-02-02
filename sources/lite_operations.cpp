#include "lite_operations.h"
#include "lite_fs.h"
#include "lite_stream.h"
#include "logger.h"
#include "platform.h"

#include <math.h>

namespace securefs
{
namespace lite
{
    static const char* get_type_name(const std::exception& e)
    {
        auto ebase = dynamic_cast<const ExceptionBase*>(&e);
        if (ebase)
            return ebase->type_name();
        return typeid(e).name();
    }

    static int get_error_number(const std::exception& e)
    {
        auto ebase = dynamic_cast<const ExceptionBase*>(&e);
        if (ebase)
            return ebase->error_number();
        return EPERM;
    }

#define SINGLE_COMMON_PROLOGUE                                                                     \
    auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);                  \
    global_logger->trace("%s %s", __func__, path);                                                 \
    std::lock_guard<FileSystem> xguard(*filesystem);                                               \
    try                                                                                            \
    {

#define SINGLE_COMMON_EPILOGUE                                                                     \
    }                                                                                              \
    catch (const CommonException& e) { return -e.error_number(); }                                 \
    catch (const SystemException& e) { return -e.error_number(); }                                 \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        global_logger->error(                                                                      \
            "%s %s encounters exception %s: %s", __func__, path, get_type_name(e), e.what());      \
        return -get_error_number(e);                                                               \
    }

    void* init(struct fuse_conn_info*)
    {
        auto args = static_cast<MountOptions*>(fuse_get_context()->private_data);
        auto fs = new FileSystem(args->root,
                                 args->name_key,
                                 args->content_key,
                                 args->xattr_key,
                                 args->block_size.value(),
                                 args->iv_size.value(),
                                 args->flags);
        global_logger->info("init");
        return fs;
    }

    void destroy(void* ptr)
    {
        auto fs = static_cast<FileSystem*>(ptr);
        global_logger->info("destroy");
        delete fs;
    }

    int statfs(const char* path, struct fuse_statvfs* buf)
    {
        SINGLE_COMMON_PROLOGUE
        filesystem->statvfs(buf);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int getattr(const char* path, fuse_stat* st)
    {
        SINGLE_COMMON_PROLOGUE
        if (!filesystem->stat(path, st))
            return -ENOENT;
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int opendir(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        auto traverser = filesystem->create_traverser(path);
        info->fh = reinterpret_cast<uintptr_t>(traverser.release());
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int releasedir(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        delete reinterpret_cast<DirectoryTraverser*>(info->fh);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int readdir(const char* path,
                void* buf,
                fuse_fill_dir_t filler,
                fuse_off_t,
                struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        auto traverser = reinterpret_cast<DirectoryTraverser*>(info->fh);
        std::string name;
        fuse_mode_t mode;
        fuse_stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        while (traverser->next(&name, &mode))
        {
            stbuf.st_mode = mode;
            int rc = filler(buf, name.c_str(), mode ? &stbuf : nullptr, 0);
            if (rc != 0)
                return -abs(rc);
        }
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int create(const char* path, fuse_mode_t mode, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        AutoClosedFile file = filesystem->open(path, O_RDWR | O_CREAT | O_EXCL, mode);
        info->fh = reinterpret_cast<uintptr_t>(file.release());
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        AutoClosedFile file = filesystem->open(path, info->flags, 0644);
        info->fh = reinterpret_cast<uintptr_t>(file.release());
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        FSCCloser()(reinterpret_cast<File*>(info->fh));
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int
    read(const char* path, char* buf, size_t size, fuse_off_t offset, struct fuse_file_info* info)
    {
        global_logger->trace(
            "%s %s (offset=%lld, size=%zu)", __func__, path, static_cast<long long>(offset), size);
        auto fp = reinterpret_cast<File*>(info->fh);
        std::lock_guard<File> xguard(*fp);
        try
        {
            return static_cast<int>(fp->read(buf, offset, size));
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error("%s %s (offset=%lld, size=%zu) encounters exception %s: %s",
                                 __func__,
                                 path,
                                 static_cast<long long>(offset),
                                 size,
                                 get_type_name(e),
                                 e.what());
            return -get_error_number(e);
        }
    }

    int write(const char* path,
              const char* buf,
              size_t size,
              fuse_off_t offset,
              struct fuse_file_info* info)
    {
        global_logger->trace(
            "%s %s (offset=%lld, size=%zu)", __func__, path, static_cast<long long>(offset), size);
        auto fp = reinterpret_cast<File*>(info->fh);
        std::lock_guard<File> xguard(*fp);
        try
        {
            fp->write(buf, offset, size);
            return static_cast<int>(size);
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error("%s %s (offset=%lld, size=%zu) encounters exception %s: %s",
                                 __func__,
                                 path,
                                 static_cast<long long>(offset),
                                 size,
                                 get_type_name(e),
                                 e.what());
            return -get_error_number(e);
        }
    }

    int flush(const char* path, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s", __func__, path);
        auto fp = reinterpret_cast<File*>(info->fh);
        std::lock_guard<File> xguard(*fp);
        try
        {
            fp->flush();
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error(
                "%s %s encounters exception %s: %s", __func__, path, get_type_name(e), e.what());
            return -get_error_number(e);
        }
    }

    int ftruncate(const char* path, fuse_off_t len, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s with length=%lld", __func__, path, static_cast<long long>(len));
        auto fp = reinterpret_cast<File*>(info->fh);
        std::lock_guard<File> xguard(*fp);
        try
        {
            fp->resize(len);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error("%s %s (length=%lld) encounters exception %s: %s",
                                 __func__,
                                 path,
                                 static_cast<long long>(len),
                                 get_type_name(e),
                                 e.what());
            return -get_error_number(e);
        }
    }

    int unlink(const char* path)
    {
        SINGLE_COMMON_PROLOGUE
        filesystem->unlink(path);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int mkdir(const char* path, fuse_mode_t mode)
    {
        SINGLE_COMMON_PROLOGUE
        filesystem->mkdir(path, mode);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int rmdir(const char* path)
    {
        SINGLE_COMMON_PROLOGUE
        filesystem->rmdir(path);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int chmod(const char* path, fuse_mode_t mode)
    {
        SINGLE_COMMON_PROLOGUE
        filesystem->chmod(path, mode);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int symlink(const char* to, const char* from)
    {
        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
        global_logger->trace("%s from=%s to=%s", __func__, from, to);
        std::lock_guard<FileSystem> xguard(*filesystem);
        try
        {
            filesystem->symlink(to, from);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error("%s from=%s to=%s encounters exception %s: %s",
                                 __func__,
                                 from,
                                 to,
                                 get_type_name(e),
                                 e.what());
            return -get_error_number(e);
        }
    }

    int link(const char* src, const char* dest)
    {
        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
        global_logger->trace("%s src=%s dest=%s", __func__, src, dest);
        std::lock_guard<FileSystem> xguard(*filesystem);
        try
        {
            filesystem->link(src, dest);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error("%s src=%s dest=%s encounters exception %s: %s",
                                 __func__,
                                 src,
                                 dest,
                                 get_type_name(e),
                                 e.what());
            return -get_error_number(e);
        }
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        SINGLE_COMMON_PROLOGUE(void) filesystem->readlink(path, buf, size);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int rename(const char* from, const char* to)
    {
        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
        global_logger->trace("%s from=%s to=%s", __func__, from, to);
        std::lock_guard<FileSystem> xguard(*filesystem);
        try
        {
            filesystem->rename(from, to);
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error("%s from=%s to=%s encounters exception %s: %s",
                                 __func__,
                                 from,
                                 to,
                                 get_type_name(e),
                                 e.what());
            return -get_error_number(e);
        }
    }

    int fsync(const char* path, int, struct fuse_file_info* info)
    {
        global_logger->trace("%s %s", __func__, path);
        auto fp = reinterpret_cast<File*>(info->fh);
        std::lock_guard<File> xguard(*fp);
        try
        {
            fp->fsync();
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error(
                "%s %s encounters exception %s: %s", __func__, path, get_type_name(e), e.what());
            return -get_error_number(e);
        }
    }

    int truncate(const char* path, fuse_off_t len)
    {
        if (len < 0)
            return -EINVAL;

        global_logger->trace("%s %s (len=%lld)", __func__, path, static_cast<long long>(len));
        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);

        try
        {
            std::unique_lock<FileSystem> system_guard(*filesystem);
            AutoClosedFile fp = filesystem->open(path, O_RDWR, 0644);
            system_guard.release();
            std::lock_guard<File> xguard(*fp);
            fp->resize(static_cast<size_t>(len));
            return 0;
        }
        catch (const CommonException& e)
        {
            return -e.error_number();
        }
        catch (const SystemException& e)
        {
            return -e.error_number();
        }
        catch (const std::exception& e)
        {
            global_logger->error(
                "%s %s encounters exception %s: %s", __func__, path, get_type_name(e), e.what());
            return -get_error_number(e);
        }
    }

    int utimens(const char* path, const struct fuse_timespec ts[2])
    {
        SINGLE_COMMON_PROLOGUE
        filesystem->utimens(path, ts);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

#ifdef __APPLE__
    int listxattr(const char* path, char* list, size_t size)
    {
        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
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

        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
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

        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
        return filesystem->setxattr(path, name, const_cast<char*>(value), size, flags);
    }
    int removexattr(const char* path, const char* name)
    {
        auto filesystem = static_cast<FileSystem*>(fuse_get_context()->private_data);
        return filesystem->removexattr(path, name);
    }
#endif

    void init_fuse_operations(fuse_operations* opt, const std::string& data_dir, bool noxattr)
    {
        (void)data_dir;

        memset(opt, 0, sizeof(*opt));

        opt->init = &::securefs::lite::init;
        opt->destroy = &::securefs::lite::destroy;
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
