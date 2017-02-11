#pragma once

#include "file_table.h"
#include "logger.h"
#include "myutils.h"

#include <fuse.h>

#define OPT_TRACE_WITH_PATH TRACE_LOG("%s path=%s", __func__, path)
#define OPT_TRACE_WITH_PATH_OFF_LEN(off, len)                                                      \
    TRACE_LOG("%s path=%s offset=%lld length=%zu",                                                 \
              __func__,                                                                            \
              path,                                                                                \
              static_cast<long long>(off),                                                         \
              static_cast<size_t>(len))
#define OPT_TRACE_WITH_TWO_PATHS(path1, path2)                                                     \
    TRACE_LOG("%s %s=%s %s=%s", __func__, #path1, path1, #path2, path2)

#define OPT_CATCH_WITH_PATH                                                                        \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        auto ebase = dynamic_cast<const ExceptionBase*>(&e);                                       \
        auto code = ebase ? ebase->error_number() : EPERM;                                         \
        auto type_name = ebase ? ebase->type_name() : typeid(e).name();                            \
        ERROR_LOG("%s path=%s encounters exception %s (code=%d): %s",                              \
                  __func__,                                                                        \
                  path,                                                                            \
                  type_name,                                                                       \
                  code,                                                                            \
                  e.what());                                                                       \
        return -code;                                                                              \
    }

#define OPT_CATCH_WITH_PATH_OFF_LEN(off, len)                                                      \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        auto ebase = dynamic_cast<const ExceptionBase*>(&e);                                       \
        auto code = ebase ? ebase->error_number() : EPERM;                                         \
        auto type_name = ebase ? ebase->type_name() : typeid(e).name();                            \
        ERROR_LOG("%s path=%s offset=%lld length=%zu encounters exception %s (code=%d): %s",       \
                  __func__,                                                                        \
                  path,                                                                            \
                  static_cast<long long>(off),                                                     \
                  static_cast<size_t>(len),                                                        \
                  type_name,                                                                       \
                  code,                                                                            \
                  e.what());                                                                       \
        return -code;                                                                              \
    }

#define OPT_CATCH_WITH_TWO_PATHS(path1, path2)                                                     \
    catch (const std::exception& e)                                                                \
    {                                                                                              \
        auto ebase = dynamic_cast<const ExceptionBase*>(&e);                                       \
        auto code = ebase ? ebase->error_number() : EPERM;                                         \
        auto type_name = ebase ? ebase->type_name() : typeid(e).name();                            \
        ERROR_LOG("%s %s=%s %s=%s encounters exception %s (code=%d): %s",                          \
                  __func__,                                                                        \
                  #path1,                                                                          \
                  path1,                                                                           \
                  #path2,                                                                          \
                  path2,                                                                           \
                  type_name,                                                                       \
                  code,                                                                            \
                  e.what());                                                                       \
        return -code;                                                                              \
    }

namespace securefs
{
class FileStream;

namespace operations
{
    extern const std::string LOCK_FILENAME;
    struct MountOptions
    {
        optional<int> version;
        std::shared_ptr<const OSService> root;
        std::shared_ptr<FileStream> lock_stream;
        optional<key_type> master_key;
        optional<uint32_t> flags;
        optional<unsigned> block_size;
        optional<unsigned> iv_size;

        MountOptions();
        ~MountOptions();
    };

    struct FileSystemContext
    {
    public:
        FileTable table;
        std::shared_ptr<const OSService> root;
        std::shared_ptr<FileStream> lock_stream;
        id_type root_id;
        unsigned block_size;
        optional<fuse_uid_t> uid_override;
        optional<fuse_gid_t> gid_override;
        uint32_t flags;
        CryptoPP::AutoSeededRandomPool csrng;

        explicit FileSystemContext(const MountOptions& opt);

        ~FileSystemContext();
    };

    int statfs(const char*, struct fuse_statvfs*);

    void* init(struct fuse_conn_info*);

    void destroy(void* ptr);

    int getattr(const char*, struct fuse_stat*);

    int opendir(const char*, struct fuse_file_info*);

    int releasedir(const char*, struct fuse_file_info*);

    int readdir(const char*, void*, fuse_fill_dir_t, fuse_off_t, struct fuse_file_info*);

    int create(const char*, fuse_mode_t, struct fuse_file_info*);

    int open(const char*, struct fuse_file_info*);

    int release(const char*, struct fuse_file_info*);

    int read(const char*, char*, size_t, fuse_off_t, struct fuse_file_info*);

    int write(const char*, const char*, size_t, fuse_off_t, struct fuse_file_info*);

    int flush(const char*, struct fuse_file_info*);

    int truncate(const char*, fuse_off_t);

    int ftruncate(const char*, fuse_off_t, struct fuse_file_info*);

    int unlink(const char*);

    int mkdir(const char*, fuse_mode_t);

    int rmdir(const char*);

    int chmod(const char*, fuse_mode_t);

    int chown(const char* path, fuse_uid_t uid, fuse_gid_t gid);

    int symlink(const char* to, const char* from);

    int readlink(const char* path, char* buf, size_t size);

    int rename(const char*, const char*);

    int link(const char*, const char*);

    int fsync(const char* path, int isdatasync, struct fuse_file_info* fi);

    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi);

    int utimens(const char* path, const struct fuse_timespec ts[2]);

#ifdef __APPLE__
    int listxattr(const char* path, char* list, size_t size);
    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position);

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position);
    int removexattr(const char* path, const char* name);
#endif
}
}
