#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#include "utils.h"
#include "exceptions.h"
#include "streams.h"
#include "operations.h"

#include <fuse.h>
#include <json.hpp>

#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <typeinfo>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#else
#include <attr/xattr.h>
#endif

static const char* CONFIG_FILE_NAME = ".securefs.json";
static const char* CONFIG_HMAC_FILE_NAME = ".securefs.hmac-sha256";
static const unsigned MIN_ITERATIONS = 20000;
static const unsigned MIN_DERIVE_SECONDS = 1;
static const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;

void create_configuration(const void* password, size_t pass_length, const std::string& folder)
{
    using namespace securefs;
    key_type master_key, salt, key_to_encrypt_master_key;
    generate_random(master_key.data(), master_key.size());
    generate_random(salt.data(), salt.size());

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    auto actual_iterations = pbkdf.DeriveKey(key_to_encrypt_master_key.data(),
                                             key_to_encrypt_master_key.size(),
                                             0,
                                             static_cast<const byte*>(password),
                                             pass_length,
                                             salt.data(),
                                             salt.size(),
                                             MIN_ITERATIONS,
                                             MIN_DERIVE_SECONDS);
    byte IV[CONFIG_IV_LENGTH];
    byte MAC[CONFIG_MAC_LENGTH];
    generate_random(IV, sizeof(IV));

    nlohmann::json config;
    config["version"] = 1;
    config["salt"] = hexify(salt.data(), salt.size());
    config["iterations"] = actual_iterations;
    config["encrypted_key"] = {{"IV", hexify(IV, sizeof(IV))},
                               {"MAC", hexify(MAC, sizeof(MAC))},
                               {"ciphertext", hexify(master_key.data(), master_key.size())}};
    auto config_str = config.dump();

    int fd = ::open((folder + '/' + CONFIG_FILE_NAME).c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
}

void init_fuse_operations(const char* underlying_path, struct fuse_operations& opt)
{
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
    opt.rename = &securefs::operations::rename;
    opt.fsync = &securefs::operations::fsync;
    opt.fsyncdir = &securefs::operations::fsyncdir;
    opt.utimens = &securefs::operations::utimens;

#ifdef __APPLE__
    auto rc = ::listxattr(underlying_path, nullptr, 0, 0);
#else
    auto rc = ::listxattr(underlying_path, nullptr, 0);
#endif
    if (rc < 0)
        return;    // The underlying filesystem does not support extended attributes
    opt.listxattr = &securefs::operations::listxattr;
    opt.getxattr = &securefs::operations::getxattr;
    opt.setxattr = &securefs::operations::setxattr;
    opt.removexattr = &securefs::operations::removexattr;
}

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
    init_fuse_operations("/Users/rsy/secret", opt);
    return fuse_main(argc, argv, &opt, fs);
}
