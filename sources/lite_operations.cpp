#include "lite_operations.h"
#include "logger.h"

#include <stdlib.h>

namespace securefs
{
namespace lite
{
    static const char* type_name(const std::exception& e)
    {
        auto ebase = dynamic_cast<const ExceptionBase*>(&e);
        if (ebase)
            return ebase->type_name();
        return typeid(e).name();
    }

    static int error_number(const std::exception& e)
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
                         type_name(e),                                                             \
                         e.what());                                                                \
        return -error_number(e);                                                                   \
    }                                                                                              \
    abort();

    int statfs(const char* path, struct statvfs* buf)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.statvfs(buf);
        SINGLE_COMMON_EPILOGUE
    }

    int getattr(const char* path, FUSE_STAT* st)
    {
        SINGLE_COMMON_PROLOGUE
        ctx->filesystem.stat(path, st);
        SINGLE_COMMON_EPILOGUE
    }

    int opendir(const char*, struct fuse_file_info*) { return 0; }
    int releasedir(const char*, struct fuse_file_info*) { return 0; }
    int readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t, struct fuse_file_info*)
    {
        SINGLE_COMMON_PROLOGUE

        SINGLE_COMMON_EPILOGUE
    }
}
}
