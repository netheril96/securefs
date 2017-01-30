#include "lite_operations.h"
#include "lite_fs.h"
#include "lite_stream.h"
#include "logger.h"

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

    struct FileSystemContext
    {
        FileSystem filesystem;
        std::shared_ptr<securefs::Logger> logger;

        explicit FileSystemContext(const MountOptions& opt)
            : filesystem(opt.root,
                         opt.name_key,
                         opt.content_key,
                         opt.xattr_key,
                         opt.block_size.value(),
                         opt.iv_size.value(),
                         true)
            , logger(opt.logger)
        {
        }
        ~FileSystemContext() {}
    };

#define SINGLE_COMMON_PROLOGUE                                                                     \
    auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);                  \
    ctx->logger->log(LoggingLevel::VERBOSE, "%s %s", __func__, path);                              \
    std::lock_guard<FileSystem> xguard(ctx->filesystem);                                           \
    try                                                                                            \
    {

#define SINGLE_COMMON_EPILOGUE                                                                     \
    }                                                                                              \
    catch (const CommonException& e) { return -e.error_number(); }                                 \
    catch (const SystemException& e) { return -e.error_number(); }                                 \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        ctx->logger->log(LoggingLevel::ERROR,                                                      \
                         "%s %s encounters exception %s: %s",                                      \
                         __func__,                                                                 \
                         path,                                                                     \
                         get_type_name(e),                                                         \
                         e.what());                                                                \
        return -get_error_number(e);                                                               \
    }

    void* init(struct fuse_conn_info*)
    {
        auto args = static_cast<MountOptions*>(fuse_get_context()->private_data);
        auto fsctx = new FileSystemContext(*args);
        args->logger->log(LoggingLevel::VERBOSE, "init");
        return fsctx;
    }

    void destroy(void* ptr)
    {
        auto fsctx = static_cast<FileSystemContext*>(ptr);
        fsctx->logger->log(LoggingLevel::VERBOSE, "destroy");
        delete fsctx;
    }

    int statfs(const char* path, struct statvfs* buf)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.statvfs(buf);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int getattr(const char* path, FUSE_STAT* st)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.stat(path, st);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int opendir(const char*, struct fuse_file_info*) { return 0; }
    int releasedir(const char*, struct fuse_file_info*) { return 0; }
    int readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t, struct fuse_file_info*)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.traverse_directory(
            path,
            [filler, buf](const std::string& name, mode_t mode) -> bool {
                FUSE_STAT st = {};
                st.st_mode = mode;
                return filler(buf, name.c_str(), &st, 0) == 0;
            },
            [ctx](const std::string& name) {
                ctx->logger->log(LoggingLevel::WARNING,
                                 "Encounters invalid encrypted filename: %s",
                                 name.c_str());
            });
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int create(const char* path, mode_t mode, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        AutoClosedFile file = ctx->filesystem.create(path, mode);
        info->fh = reinterpret_cast<uintptr_t>(file.release());
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int open(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        AutoClosedFile file = ctx->filesystem.open(path, info->flags);
        info->fh = reinterpret_cast<uintptr_t>(file.release());
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int release(const char* path, struct fuse_file_info* info)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.close(reinterpret_cast<File*>(info->fh));
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* info)
    {
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE,
                         "%s %s (offset=%lld, size=%zu)",
                         __func__,
                         path,
                         static_cast<long long>(offset),
                         size);
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s %s (offset=%lld, size=%zu) encounters exception %s: %s",
                             __func__,
                             path,
                             static_cast<long long>(offset),
                             size,
                             get_type_name(e),
                             e.what());
            return -get_error_number(e);
        }
    }

    int
    write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* info)
    {
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE,
                         "%s %s (offset=%lld, size=%zu)",
                         __func__,
                         path,
                         static_cast<long long>(offset),
                         size);
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s %s (offset=%lld, size=%zu) encounters exception %s: %s",
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
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE, "%s %s", __func__, path);
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s %s encounters exception %s: %s",
                             __func__,
                             path,
                             get_type_name(e),
                             e.what());
            return -get_error_number(e);
        }
    }

    int ftruncate(const char* path, off_t len, struct fuse_file_info* info)
    {
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE,
                         "%s %s with length=%lld",
                         __func__,
                         path,
                         static_cast<long long>(len));
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s %s (length=%lld) encounters exception %s: %s",
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
        ctx->filesystem.unlink(path);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int mkdir(const char* path, mode_t mode)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.mkdir(path, mode);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int rmdir(const char* path)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.rmdir(path);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int chmod(const char* path, mode_t mode)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.chmod(path, mode);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    int symlink(const char* to, const char* from)
    {
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE, "%s from=%s to=%s", __func__, from, to);
        std::lock_guard<FileSystem> xguard(ctx->filesystem);
        try
        {
            ctx->filesystem.symlink(to, from);
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s from=%s to=%s encounters exception %s: %s",
                             __func__,
                             from,
                             to,
                             get_type_name(e),
                             e.what());
            return -get_error_number(e);
        }
    }

    int readlink(const char* path, char* buf, size_t size)
    {
        SINGLE_COMMON_PROLOGUE
        return static_cast<int>(ctx->filesystem.readlink(path, buf, size));
        SINGLE_COMMON_EPILOGUE
    }

    int rename(const char* from, const char* to)
    {
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE, "%s from=%s to=%s", __func__, from, to);
        std::lock_guard<FileSystem> xguard(ctx->filesystem);
        try
        {
            ctx->filesystem.rename(from, to);
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s from=%s to=%s encounters exception %s: %s",
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
        auto ctx = static_cast<FileSystemContext*>(fuse_get_context()->private_data);
        ctx->logger->log(LoggingLevel::VERBOSE, "%s %s", __func__, path);
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
            ctx->logger->log(LoggingLevel::ERROR,
                             "%s %s encounters exception %s: %s",
                             __func__,
                             path,
                             get_type_name(e),
                             e.what());
            return -get_error_number(e);
        }
    }

    int utimens(const char* path, const struct timespec ts[2])
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.utimens(path, ts);
        return 0;
        SINGLE_COMMON_EPILOGUE
    }

    void init_fuse_operations(fuse_operations* opt,
                              const std::string& data_dir,
                              const std::string& mount_dir)
    {
        (void)data_dir;
        (void)mount_dir;

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
        opt->readlink = &::securefs::lite::readlink;
        opt->rename = &::securefs::lite::rename;
        opt->fsync = &::securefs::lite::fsync;
        opt->utimens = &::securefs::lite::utimens;
    }
}
}
