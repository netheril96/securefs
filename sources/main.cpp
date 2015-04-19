#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#include "utils.h"
#include "exceptions.h"
#include "streams.h"
#include "operations.h"

#include <fuse.h>

#include <typeinfo>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    int dir_fd = ::open("/Users/rsy/secret", O_RDONLY);
    securefs::key_type master_key{};
    securefs::operations::FileSystem* fs;
    try
    {
        fs = new securefs::operations::FileSystem(dir_fd, master_key, 0);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Error initializing filesystem\n%s: %s\n", typeid(e).name(), e.what());
        return -1;
    }
    try
    {
        fs->table.create_as(fs->root_id, securefs::FileBase::DIRECTORY);
    }
    catch (...)
    {
        // ignore
    }
    struct fuse_operations opt;
    memset(&opt, 0, sizeof(opt));
    opt.init = securefs::operations::init;
    opt.destroy = securefs::operations::destroy;
    opt.getattr = securefs::operations::getattr;
    return fuse_main(argc, argv, &opt, fs);
}
