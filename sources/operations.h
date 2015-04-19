#pragma once
#include "file_table.h"

#define FUSE_USE_VERSION 27
#include <fuse.h>

#include <sys/stat.h>
#include <sys/types.h>

namespace securefs
{
namespace operations
{
    struct FileSystem
    {
        FileTable table;
        id_type root_id;

        explicit FileSystem(int dir_fd, const key_type& master_key, uint32_t flags)
            : table(dir_fd, master_key, flags)
        {
            memset(root_id.data(), 0, root_id.size());
        }

        ~FileSystem() {}
    };

    void* init(struct fuse_conn_info*) { return fuse_get_context()->private_data; }

    void destroy(void* ptr) { delete static_cast<FileSystem*>(ptr); }

    int getattr(const char*, struct stat*);
}
}
