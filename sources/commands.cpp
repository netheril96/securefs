#include "exceptions.h"
#include "operations.h"
#include "streams.h"
#include "utils.h"
#include "xattr_compat.h"

#include <cryptopp/secblock.h>
#include <format.h>
#include <fuse.h>
#include <json.hpp>
#include <tclap/CmdLine.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string.h>
#include <typeinfo>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <unistd.h>

namespace
{

static const char* VERSION_HEADER = "version=1";
static const char* CONFIG_FILE_NAME = ".securefs.json";
static const char* CONFIG_TMP_FILE_NAME = ".securefs.json.tmp";
static const unsigned MIN_ITERATIONS = 20000;
static const unsigned MIN_DERIVE_SECONDS = 1;
static const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;
static const size_t MAX_PASS_LEN = 4000;

void lock_base_directory(int dir_fd)
{
    auto rc = ::flock(dir_fd, LOCK_EX | LOCK_NB);
    if (rc < 0)
    {
        if (errno == EWOULDBLOCK)
        {
            throw std::runtime_error(
                "Error: another process is holding the lock on the underlying directory\n");
        }
        else
        {
            throw std::runtime_error(
                fmt::format("Error locking base directory: {}", securefs::sane_strerror(errno)));
        }
    }
}

nlohmann::json generate_config(int version,
                               const securefs::key_type& master_key,
                               const securefs::key_type& salt,
                               const void* password,
                               size_t pass_len,
                               unsigned block_size,
                               unsigned iv_size,
                               unsigned rounds = 0)
{
    nlohmann::json config;
    config["version"] = version;
    securefs::key_type key_to_encrypt, encrypted_master_key;
    config["iterations"] = securefs::pbkdf_hmac_sha256(password,
                                                       pass_len,
                                                       salt.data(),
                                                       salt.size(),
                                                       rounds ? rounds : MIN_ITERATIONS,
                                                       rounds ? 0 : MIN_DERIVE_SECONDS,
                                                       key_to_encrypt.data(),
                                                       key_to_encrypt.size());
    config["salt"] = securefs::hexify(salt);

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    securefs::generate_random(iv, sizeof(iv));

    securefs::aes_gcm_encrypt(master_key.data(),
                              master_key.size(),
                              VERSION_HEADER,
                              strlen(VERSION_HEADER),
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
    if (version == 2)
    {
        config["block_size"] = block_size;
        config["iv_size"] = iv_size;
    }
    return config;
}

bool parse_config(const nlohmann::json& config,
                  const void* password,
                  size_t pass_len,
                  securefs::key_type& master_key,
                  unsigned& block_size,
                  unsigned& iv_size)
{
    using namespace securefs;
    unsigned version = config["version"];

    if (version == 1)
    {
        block_size = 4096;
        iv_size = 32;
    }
    else if (version == 2)
    {
        block_size = config.at("block_size");
        iv_size = config.at("iv_size");
    }
    else
    {
        throw InvalidArgumentException(fmt::format("Unsupported version {}", version));
    }

    unsigned iterations = config.at("iterations");

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt, encrypted_key, key_to_encrypt_master_key;

    std::string salt_hex = config.at("salt");
    auto&& encrypted_key_json_value = config.at("encrypted_key");
    std::string iv_hex = encrypted_key_json_value.at("IV");
    std::string mac_hex = encrypted_key_json_value.at("MAC");
    std::string ekey_hex = encrypted_key_json_value.at("key");

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
                           VERSION_HEADER,
                           strlen(VERSION_HEADER),
                           key_to_encrypt_master_key.data(),
                           key_to_encrypt_master_key.size(),
                           iv,
                           sizeof(iv),
                           mac,
                           sizeof(mac),
                           master_key.data());
}

nlohmann::json read_config(int dir_fd)
{
    using namespace securefs;
    int config_fd = ::openat(dir_fd, CONFIG_FILE_NAME, O_RDONLY);
    if (config_fd < 0)
        throw std::runtime_error(
            fmt::format("Error opening {}: {}", CONFIG_FILE_NAME, sane_strerror(errno)));

    POSIXFileStream config_stream(config_fd);
    std::string config_str(config_stream.size(), 0);
    if (config_str.empty())
        throw std::runtime_error("Error parsing config file: file is empty");

    config_stream.read(&config_str[0], 0, config_str.size());
    return nlohmann::json::parse(config_str);
}

size_t try_read_password_with_confirmation(void* password, size_t length)
{
    CryptoPP::AlignedSecByteBlock second_password(length);
    static const char* first_prompt = "Password: ";
    static const char* second_prompt = "Retype password: ";
    size_t len1, len2;
    try
    {
        len1 = securefs::secure_read_password(stdin, first_prompt, password, length);
        len2 = securefs::secure_read_password(stdin, second_prompt, second_password.data(), length);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Warning: failed to disable echoing of passwords (%s)\n", e.what());
        len1 = securefs::insecure_read_password(stdin, first_prompt, password, length);
        len2 = securefs::insecure_read_password(
            stdin, second_prompt, second_password.data(), length);
    }
    if (len1 != len2 || memcmp(password, second_password.data(), len1) != 0)
    {
        throw std::runtime_error("Error: mismatched passwords");
    }
    return len1;
}

int open_and_lock_base_dir(const std::string& path)
{
    int folder_fd = ::open(path.c_str(), O_RDONLY);
    if (folder_fd < 0)
        throw std::runtime_error(
            fmt::format("Error opening directory {}: {}", path, securefs::sane_strerror(errno)));
    lock_base_directory(folder_fd);
    return folder_fd;
}

int create_filesys(int argc, char** argv)
{
    using namespace securefs;
    TCLAP::CmdLine cmdline("Create a securefs filesystem");
    TCLAP::SwitchArg stdinpass(
        "s", "stdinpass", "Read password from stdin directly (useful for piping)");
    TCLAP::ValueArg<unsigned> rounds(
        "r",
        "rounds",
        "Specify how many rounds of PBKDF2 are applied (0 for automatic)",
        false,
        0,
        "integer");
    TCLAP::UnlabeledValueArg<std::string> dir(
        "dir", "Directory where the data are stored", true, "", "directory");
    cmdline.add(&stdinpass);
    cmdline.add(&rounds);
    cmdline.add(&dir);
    cmdline.parse(argc, argv);

    int folder_fd = open_and_lock_base_dir(dir.getValue());

    int config_fd = -1;
    try
    {
        key_type master_key, salt;
        generate_random(master_key.data(), master_key.size());
        generate_random(salt.data(), salt.size());

        CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
        size_t pass_len;
        if (stdinpass.getValue())
            pass_len = insecure_read_password(stdin, nullptr, password.data(), password.size());
        else
            pass_len = try_read_password_with_confirmation(password.data(), password.size());

        auto config
            = generate_config(
                  2, master_key, salt, password.data(), pass_len, 4096, 12, rounds.getValue())
                  .dump();

        config_fd = ::openat(folder_fd, CONFIG_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (config_fd < 0)
            throw std::runtime_error(fmt::format(
                "Error creating {} for writing: {}", CONFIG_FILE_NAME, sane_strerror(errno)));
        POSIXFileStream config_stream(config_fd);
        config_stream.write(config.data(), 0, config.size());

        operations::FSOptions opt;
        opt.version = 2;
        opt.dir_fd = folder_fd;
        opt.master_key = master_key;
        opt.flags = 0;
        opt.block_size = 4096;
        opt.iv_size = 12;
        operations::FileSystem fs(opt);
        auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
        root->set_uid(getuid());
        root->set_gid(getgid());
        root->set_mode(S_IFDIR | 0755);
        root->set_nlink(1);
        root->flush();
        fputs("Filesystem successfully created\n", stderr);
        return 0;
    }
    catch (...)
    {
        if (config_fd >= 0)
            ::unlinkat(folder_fd, CONFIG_FILE_NAME, 0);
        throw;
    }
}

void init_fuse_operations(const char* underlying_path, struct fuse_operations& opt, bool xattr)
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
    opt.link = &securefs::operations::link;
    opt.fsync = &securefs::operations::fsync;
    opt.fsyncdir = &securefs::operations::fsyncdir;
    opt.utimens = &securefs::operations::utimens;
    if (!xattr)
        return;

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

size_t try_read_password(void* password, size_t size)
{
    static const char* prompt = "Password: ";
    try
    {
        return securefs::secure_read_password(stdin, prompt, password, size);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Warning: failed to disable echoing of passwords (%s)\n", e.what());
        return securefs::insecure_read_password(stdin, prompt, password, size);
    }
}

int mount_filesys(int argc, char** argv)
{
    using namespace securefs;
    TCLAP::CmdLine cmdline("Mount the filesystem");
    TCLAP::SwitchArg stdinpass(
        "s", "stdinpass", "Read password from stdin directly (useful for piping)");
    TCLAP::SwitchArg background("b", "background", "Run securefs in the background");
    TCLAP::SwitchArg insecure(
        "i", "insecure", "Disable all integrity verification (insecure mode)");
    TCLAP::SwitchArg noxattr("x", "noxattr", "Disable built-in xattr support");
    TCLAP::ValueArg<std::string> log(
        "", "log", "Path of the log file (may contain sensitive information", false, "", "path");

    TCLAP::UnlabeledValueArg<std::string> data_dir(
        "data_dir", "Directory where the data are stored", true, "", "directory");
    TCLAP::UnlabeledValueArg<std::string> mount_point(
        "mount_point", "Mount point", true, "", "directory");
    cmdline.add(&stdinpass);
    cmdline.add(&background);
    cmdline.add(&insecure);
    cmdline.add(&noxattr);
    cmdline.add(&log);
    cmdline.add(&data_dir);
    cmdline.add(&mount_point);
    cmdline.parse(argc, argv);

    {
        struct rlimit rl;
        int rc = ::getrlimit(RLIMIT_NOFILE, &rl);
        if (rc != 0)
            throw std::runtime_error(securefs::sane_strerror(errno));
        rl.rlim_cur = 10240 * 16;
        do
        {
            rl.rlim_cur /= 2;
            rc = ::setrlimit(RLIMIT_NOFILE, &rl);
        } while (rc < 0 && rl.rlim_cur >= 1024);
        if (rc != 0)
            fprintf(stderr,
                    "Fail to raise the limit of number of file descriptors: %s\nYou may encounter "
                    "\"Too many opened files\" errors later\n",
                    sane_strerror(errno).c_str());
        else
            fprintf(stderr,
                    "Setting limit of number of file descriptors to %d\n",
                    static_cast<int>(rl.rlim_cur));
    }

    operations::FSOptions fsopt;
    fsopt.dir_fd = open_and_lock_base_dir(data_dir.getValue());

    auto config_json = read_config(fsopt.dir_fd.get());
    auto version = config_json.at("version").get<int>();
    fsopt.version = version;
    if (version != 1 && version != 2)
        throw std::runtime_error(fmt::format("Unkown format version {}", version));

    fprintf(stderr,
            "Mounting filesystem stored at %s onto %s\nFormat version: %u\n",
            data_dir.getValue().c_str(),
            mount_point.getValue().c_str(),
            version);

    {
        CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
        size_t pass_len = 0;
        if (stdinpass.getValue())
            pass_len = insecure_read_password(stdin, nullptr, password.data(), password.size());
        else
            pass_len = try_read_password(password.data(), password.size());

        fsopt.master_key.set_init(true);
        fsopt.block_size.set_init(true);
        fsopt.iv_size.set_init(true);
        if (!parse_config(config_json,
                          password,
                          pass_len,
                          fsopt.master_key.get(),
                          fsopt.block_size.get(),
                          fsopt.iv_size.get()))
            throw std::runtime_error("Error: wrong password");
    }

    if (log.isSet())
        fsopt.logger = std::make_shared<FileLogger>(LoggingLevel::WARN,
                                                    fopen(log.getValue().c_str(), "w+b"));
    else
        fsopt.logger = std::make_shared<FileLogger>(LoggingLevel::WARN, stderr);

    fsopt.flags = 0;
    if (insecure.getValue())
        fsopt.flags.get() |= FileTable::NO_AUTHENTICATION;

    struct fuse_operations opt;
    init_fuse_operations(data_dir.getValue().c_str(), opt, !noxattr.getValue());

    std::vector<const char*> fuse_args;
    fuse_args.push_back("securefs");
    fuse_args.push_back("-s");
    if (!background.getValue())
        fuse_args.push_back("-f");
    fuse_args.push_back(mount_point.getValue().c_str());

    return fuse_main(
        static_cast<int>(fuse_args.size()), const_cast<char**>(fuse_args.data()), &opt, &fsopt);
}

int chpass_filesys(int argc, char** argv)
{
    using namespace securefs;
    TCLAP::CmdLine cmdline("Change the password of a given filesystem");
    TCLAP::SwitchArg stdinpass(
        "s", "stdinpass", "Read password from stdin directly (useful for piping)");
    TCLAP::ValueArg<unsigned> rounds(
        "r",
        "rounds",
        "Specify how many rounds of PBKDF2 are applied (0 for automatic)",
        false,
        0,
        "integer");
    TCLAP::UnlabeledValueArg<std::string> dir(
        "dir", "Directory where the data are stored", true, "", "directory");
    cmdline.add(&stdinpass);
    cmdline.add(&rounds);
    cmdline.add(&dir);
    cmdline.parse(argc, argv);

    int folder_fd = open_and_lock_base_dir(dir.getValue());

    auto config_json = read_config(folder_fd);
    key_type master_key;

    CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
    size_t pass_len = try_read_password(password.data(), password.size());

    unsigned block_size, iv_size;
    if (!parse_config(config_json, password, pass_len, master_key, block_size, iv_size))
        throw std::runtime_error("Error: wrong password");

    fprintf(stderr, "Authentication success. Now enter new password.\n");
    pass_len = try_read_password_with_confirmation(password, password.size());

    key_type salt;
    generate_random(salt.data(), salt.size());
    auto config = generate_config(config_json.at("version"),
                                  master_key,
                                  salt,
                                  password.data(),
                                  pass_len,
                                  block_size,
                                  iv_size,
                                  rounds.getValue())
                      .dump();

    int config_fd = ::openat(folder_fd, CONFIG_TMP_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (config_fd < 0)
        throw std::runtime_error(fmt::format(
            "Error creating {} for writing: {}", CONFIG_TMP_FILE_NAME, sane_strerror(errno)));
    POSIXFileStream config_stream(config_fd);
    config_stream.write(config.data(), 0, config.size());

    int rc = ::renameat(folder_fd, CONFIG_TMP_FILE_NAME, folder_fd, CONFIG_FILE_NAME);
    if (rc < 0)
        throw std::runtime_error(fmt::format("Error moving {} to {}: {}",
                                             CONFIG_TMP_FILE_NAME,
                                             CONFIG_FILE_NAME,
                                             sane_strerror(errno)));
    fputs("Password change success\n", stderr);
    return 0;
}

typedef int (*command_function)(int, char**);

struct CommandInfo
{
    const char* short_cmd;
    const char* long_cmd;
    const char* help;
    command_function function;
};

const CommandInfo commands[]
    = {{"m", "mount", "Mount filesystem", &mount_filesys},
       {"c", "create", "Create a new filesystem", &create_filesys},
       {nullptr, "chpass", "Change the password of existing filesystem", &chpass_filesys}};

const char* get_nonnull(const char* a, const char* b)
{
    if (a)
        return a;
    if (b)
        return b;
    return nullptr;
}

int print_usage(FILE* fp)
{
    fputs("securefs [command] [args]\n\n    Available commands:\n\n", fp);
    for (auto&& info : commands)
    {
        if (info.short_cmd && info.long_cmd)
            fprintf(fp, "    %s, %s: %s\n", info.short_cmd, info.long_cmd, info.help);
        else
            fprintf(fp, "    %s: %s\n", get_nonnull(info.short_cmd, info.long_cmd), info.help);
    }
    fputs("\nCall \"securefs [command] -h\" to learn the detailed usage of the command\n", fp);
    return 8;
}
}

namespace securefs
{
int commands_main(int argc, char** argv)
{
    try
    {
        if (argc < 2)
            return print_usage(stderr);
        argc--;
        argv++;
        for (auto&& info : commands)
        {
            if ((info.long_cmd && strcmp(argv[0], info.long_cmd) == 0)
                || (info.short_cmd && strcmp(argv[0], info.short_cmd) == 0))
                return info.function(argc, argv);
        }
        return print_usage(stderr);
    }
    catch (const TCLAP::ArgException& e)
    {
        fprintf(
            stderr, "Error parsing arguments: %s at %s\n", e.error().c_str(), e.argId().c_str());
        return 5;
    }
    catch (const std::runtime_error& e)
    {
        fprintf(stderr, "%s\n", e.what());
        return 1;
    }
    catch (const securefs::ExceptionBase& e)
    {
        fprintf(stderr, "%s: %s\n", e.type_name(), e.message().c_str());
        return 2;
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "%s: %s\n", typeid(e).name(), e.what());
        return 3;
    }
}
}
