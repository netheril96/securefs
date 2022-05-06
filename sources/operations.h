#pragma once

#include "file_table.h"
#include "logger.h"
#include "myutils.h"

#include <fuse.h>

namespace securefs
{
class FileStream;

namespace operations
{
    extern const char* LOCK_FILENAME;
    struct MountOptions
    {
        optional<int> version;
        std::shared_ptr<const OSService> root;
        CryptoPP::AlignedSecByteBlock master_key;
        optional<uint32_t> flags;
        optional<unsigned> block_size;
        optional<unsigned> iv_size;
        unsigned max_padding_size = 0;
        std::shared_ptr<FileStream> lock_stream;

        MountOptions();
        ~MountOptions();
    };

    struct FileSystemContext
    {
    private:
        static key_type from_cryptopp_key(const CryptoPP::AlignedSecByteBlock& key)
        {
            if (key.size() != KEY_LENGTH)
                throwInvalidArgumentException("Invalid key length");
            key_type result;
            memcpy(result.data(), key.data(), key.size());
            return result;
        }

    public:
        ShardedFileTableImpl table;
        std::shared_ptr<const OSService> root;
        id_type root_id;
        unsigned block_size;
        optional<fuse_uid_t> uid_override;
        optional<fuse_gid_t> gid_override;
        uint32_t flags;
        std::shared_ptr<FileStream> lock_stream;

        explicit FileSystemContext(const MountOptions& opt);

        ~FileSystemContext();
    };

    void init_fuse_operations(struct fuse_operations* opt, bool xattr);

    int statfs(const char*, struct fuse_statvfs*);

    void* init(struct fuse_conn_info*);

    void destroy(void* ptr);

    int getattr(const char*, struct fuse_stat*);

    int fgetattr(const char*, struct fuse_stat*, struct fuse_file_info*);

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
}    // namespace operations
}    // namespace securefs
