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
        auto root = fs->table.create_as(fs->root_id, securefs::FileBase::DIRECTORY);
        root->set_uid(getuid());
        root->set_gid(getgid());
        root->set_mode(S_IFDIR | 0755);
        root->set_nlink(1);
    }
    catch (...)
    {
        // ignore
    }
    struct fuse_operations opt;
    memset(&opt, 0, sizeof(opt));
    opt.getattr = &securefs::operations::getattr;
    opt.init = &securefs::operations::init;
    opt.destroy = &securefs::operations::destroy;
    opt.opendir = &securefs::operations::opendir;
    opt.releasedir = &securefs::operations::releasedir;
    opt.readdir = &securefs::operations::readdir;
    opt.create = &securefs::operations::create;
    opt.open = &securefs::operations::open;
    opt.read = &securefs::operations::read;
    opt.write = &securefs::operations::write;
    opt.truncate = &securefs::operations::truncate;
    opt.unlink = &securefs::operations::unlink;
    opt.mkdir = &securefs::operations::mkdir;
    opt.rmdir = &securefs::operations::rmdir;
    opt.release = &securefs::operations::release;
    opt.ftruncate = &securefs::operations::ftruncate;
    opt.flush = &securefs::operations::flush;
    opt.chmod = &securefs::operations::chmod;
    opt.chown = &securefs::operations::chown;
    opt.symlink = &securefs::operations::symlink;
    opt.readlink = &securefs::operations::readlink;
    return fuse_main(argc, argv, &opt, fs);
}
