#ifdef UNIT_TEST
#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#endif

#include "utils.h"
#include "exceptions.h"
#include "streams.h"
#include "operations.h"

#include <fuse.h>
#include <json.hpp>
#include <format.h>

#include <typeinfo>
#include <memory>
#include <algorithm>
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
static const size_t MAX_PASS_LEN = 1024;

nlohmann::json generate_config(const securefs::key_type& master_key,
                               const securefs::key_type& salt,
                               const void* password,
                               size_t pass_len)
{
    nlohmann::json config;
    config["version"] = 1;
    securefs::key_type key_to_encrypt, encrypted_master_key;
    config["iterations"] = securefs::pbkdf_hmac_sha256(password,
                                                       pass_len,
                                                       salt.data(),
                                                       salt.size(),
                                                       MIN_ITERATIONS,
                                                       MIN_DERIVE_SECONDS,
                                                       key_to_encrypt.data(),
                                                       key_to_encrypt.size());
    config["salt"] = securefs::hexify(salt);

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    securefs::generate_random(iv, sizeof(iv));

    securefs::aes_gcm_encrypt(master_key.data(),
                              master_key.size(),
                              nullptr,
                              0,
                              key_to_encrypt.data(),
                              key_to_encrypt.size(),
                              iv,
                              sizeof(iv),
                              mac,
                              sizeof(mac),
                              encrypted_master_key.data());

    config["encrypted_key"] = {{"IV", securefs::hexify(iv, sizeof(iv))},
                               {"MAC", securefs::hexify(mac, sizeof(mac))},
                               {"key", securefs::hexify(encrypted_master_key)}};
    return config;
}

bool parse_config(const nlohmann::json& config,
                  const void* password,
                  size_t pass_len,
                  securefs::key_type& master_key)
{
    using namespace securefs;
    unsigned version = config["version"];
    if (version != 1)
        throw InvalidArgumentException(fmt::format("Unsupported version {}", version));
    unsigned iterations = config["iterations"];

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt, encrypted_key, key_to_encrypt_master_key;

    std::string salt_hex = config["salt"];
    std::string iv_hex = config["encrypted_key"]["iv"];
    std::string mac_hex = config["encrypted_key"]["mac"];
    std::string ekey_hex = config["encrypted_key"]["ciphertext"];

    parse_hex(salt_hex, salt.data(), salt.size());
    parse_hex(iv_hex, iv, sizeof(iv));
    parse_hex(mac_hex, mac, sizeof(mac));
    parse_hex(ekey_hex, encrypted_key.data(), encrypted_key.size());

    pbkdf_hmac_sha256(password,
                      pass_len,
                      salt.data(),
                      salt.size(),
                      iterations,
                      0,
                      key_to_encrypt_master_key.data(),
                      key_to_encrypt_master_key.size());

    return aes_gcm_decrypt(encrypted_key.data(),
                           encrypted_key.size(),
                           nullptr,
                           0,
                           key_to_encrypt_master_key.data(),
                           key_to_encrypt_master_key.size(),
                           iv,
                           sizeof(iv),
                           mac,
                           sizeof(mac),
                           master_key.data());
}

size_t try_read_password(void* password, size_t length)
{
    std::unique_ptr<byte[]> second_password(new byte[length]);
    static const char* first_prompt = "Password: ";
    static const char* second_prompt = "Retype password: ";
    size_t len1, len2;
    try
    {
        len1 = securefs::secure_read_password(stdin, first_prompt, password, length);
        len2 = securefs::secure_read_password(stdin, second_prompt, second_password.get(), length);
    }
    catch (const std::exception& e)
    {
        fmt::print(stderr, "Warning: failed to disable echoing of passwords ({})\n", e.what());
        len1 = securefs::insecure_read_password(stdin, first_prompt, password, length);
        len2
            = securefs::insecure_read_password(stdin, second_prompt, second_password.get(), length);
    }
    if (len1 != len2 || memcmp(password, second_password.get(), len1) != 0)
    {
        fmt::print(stderr, "Error: mismatched passwords\n");
        exit(1);
    }
    return len1;
}

void create_filesys(const std::string& folder)
{
    using namespace securefs;
    int folder_fd = ::open(folder.c_str(), O_RDONLY);
    if (folder_fd < 0)
        throw OSException(errno);
    FileDescriptorGuard guard_folder_fd(folder_fd);

    key_type master_key, salt;
    generate_random(master_key.data(), master_key.size());
    generate_random(salt.data(), salt.size());

    byte password[MAX_PASS_LEN];
    auto pass_len = try_read_password(password, sizeof(password));
    auto config = generate_config(master_key, salt, password, pass_len).dump();

    byte hmac[32];
    hmac_sha256_calculate(
        config.data(), config.size(), master_key.data(), master_key.size(), hmac, sizeof(hmac));

    auto config_fd = ::openat(folder_fd, CONFIG_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (config_fd < 0)
        throw OSException(errno);
    POSIXFileStream config_stream(config_fd);
    config_stream.write(config.data(), 0, config.size());

    auto hmac_fd = ::openat(folder_fd, CONFIG_HMAC_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (hmac_fd < 0)
        throw OSException(errno);
    POSIXFileStream config_hmac_stream(hmac_fd);
    config_hmac_stream.write(hmac, 0, sizeof(hmac));

    operations::FileSystem fs(folder_fd, master_key, 0);
    auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
    root->set_uid(getuid());
    root->set_gid(getgid());
    root->set_mode(S_IFDIR | 0755);
    root->set_nlink(1);
    root->flush();
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
#ifdef UNIT_TEST
    Catch::Session s;
    return s.run(argc, argv);
#else
    try
    {
        if (argc == 3 && strcmp(argv[1], "create") == 0)
        {
            create_filesys(argv[2]);
            fmt::print(stderr, "Success in creating a new secure filesystem at {}\n", argv[2]);
            return 0;
        }
        else
        {
            fmt::print(stderr, "Unrecognized command line arguments\n");
            return 2;
        }
    }
    catch (const std::exception& e)
    {
        fmt::print(stderr, "Error: {}\n", e.what());
        return 1;
    }
#endif
}
