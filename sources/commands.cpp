#include "utils.h"
#include "exceptions.h"
#include "streams.h"
#include "operations.h"

#include <fuse.h>
#include <json.hpp>
#include <format.h>
#include <tclap/CmdLine.h>
#include <cryptopp/secblock.h>

#include <typeinfo>
#include <vector>
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <typeinfo>
#include <string.h>
#include <unordered_map>

#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#else
#include <attr/xattr.h>
#endif

namespace
{
struct command_args;
typedef int (*command_action)(const command_args&);

struct command_args
{
    command_action action;
    std::string underlying_path, mount_point, log_filename;
    bool no_check = false, single_threaded = false, foreground = false, debug = false,
         log_to_stderr = false, no_log = false, stdinpass = false, readonly = false;
};

void parse_args(int argc, char** argv, command_args& output)
{
    TCLAP::CmdLine cmdline(
        "securefs: a filesystem in userspace that transparently encrypts and authenticates data",
        ' ',
        "0.1");
    TCLAP::SwitchArg no_check(
        "", "no_check", "Disable verification of authentication codes", cmdline, false);
    TCLAP::SwitchArg single_threaded(
        "s", "single_threaded", "Disable usage of multithreading", cmdline, false);
    TCLAP::SwitchArg foreground(
        "f",
        "foreground",
        "Request that the program stays in the foreground; also outputs logs to stderr",
        cmdline,
        false);
    TCLAP::SwitchArg debug(
        "d", "debug", "Output FUSE debug information; imply foreground", cmdline, false);
    TCLAP::SwitchArg stdinpass("", "stdinpass", "Read passwords from stdin", cmdline, false);
    TCLAP::SwitchArg readonly(
        "r", "readonly", "Mount the filesystem in read-only mode", cmdline, false);
    TCLAP::ValueArg<std::string> mountpoint(
        "p", "point", "The mount point", false, "", "dirname", cmdline);
    TCLAP::SwitchArg no_log("", "no_log", "Disable logging", cmdline, false);
    TCLAP::ValueArg<std::string> log_filename(
        "l", "log", "Log file name", false, "", "filename", cmdline);

    TCLAP::ValueArg<std::string> create(
        "c", "create", "Create a new secure filesystem", true, "", "dirname");
    TCLAP::ValueArg<std::string> mount(
        "m", "mount", "Mount a given secure filesystem", true, "", "dirname");
    TCLAP::ValueArg<std::string> viewlog(
        "", "viewlog", "View the encrypted log file", true, "", "filename");

    std::vector<TCLAP::Arg*> xor_args{&create, &mount, &viewlog};
    cmdline.xorAdd(xor_args);

    cmdline.parse(argc, argv);
    output.mount_point.swap(mountpoint.getValue());
    output.no_check = no_check.getValue();
    output.single_threaded = single_threaded.getValue();
    output.foreground = foreground.getValue() | debug.getValue();
    output.readonly = readonly.getValue();
    output.stdinpass = stdinpass.getValue();
    output.debug = debug.getValue();
    output.no_log = no_log.getValue();
    output.log_filename.swap(log_filename.getValue());
    output.log_to_stderr = output.foreground;

    if (create.isSet())
    {
        int create_filesys(const command_args&);
        output.action = &create_filesys;
        output.underlying_path.swap(create.getValue());
    }
    else if (mount.isSet())
    {
        int mount_filesys(const command_args&);
        output.action = &mount_filesys;
        output.underlying_path.swap(mount.getValue());
    }
    else if (viewlog.isSet())
    {
        int viewlog_filesys(const command_args&);
        output.action = &viewlog_filesys;
        output.log_filename.swap(viewlog.getValue());
    }
}

static const char* CONFIG_FILE_NAME = ".securefs.json";
static const char* CONFIG_HMAC_FILE_NAME = ".securefs.hmac-sha256";
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

void read_hmac(int dir_fd, void* buffer, size_t size)
{
    using namespace securefs;
    int hmac_fd = ::openat(dir_fd, CONFIG_HMAC_FILE_NAME, O_RDONLY);
    if (hmac_fd < 0)
    {
        throw std::runtime_error(
            fmt::format("Error opening {}: {}", CONFIG_HMAC_FILE_NAME, sane_strerror(errno)));
    }

    POSIXFileStream hmac_stream(hmac_fd);
    if (hmac_stream.size() != size)
        throw std::runtime_error(fmt::format("Wrong size of {}: expect {}, get {}",
                                             CONFIG_HMAC_FILE_NAME,
                                             size,
                                             hmac_stream.size()));
    hmac_stream.read(buffer, 0, size);
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

int create_filesys(const command_args& args)
{
    using namespace securefs;
    int folder_fd = ::open(args.underlying_path.c_str(), O_RDONLY);
    if (folder_fd < 0)
        throw std::runtime_error(fmt::format(
            "Error opening directory {}: {}", args.underlying_path, sane_strerror(errno)));
    lock_base_directory(folder_fd);

    int config_fd = -1, hmac_fd = -1;
    try
    {
        key_type master_key, salt;
        generate_random(master_key.data(), master_key.size());
        generate_random(salt.data(), salt.size());

        CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
        size_t pass_len;
        if (args.stdinpass)
            pass_len = insecure_read_password(stdin, nullptr, password.data(), password.size());
        else
            pass_len = try_read_password_with_confirmation(password.data(), password.size());

        auto config = generate_config(master_key, salt, password.data(), pass_len).dump();

        byte hmac[CONFIG_MAC_LENGTH];
        hmac_sha256_calculate(
            config.data(), config.size(), master_key.data(), master_key.size(), hmac, sizeof(hmac));

        config_fd = ::openat(folder_fd, CONFIG_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (config_fd < 0)
            throw std::runtime_error(fmt::format(
                "Error creating {} for writing: {}", CONFIG_FILE_NAME, sane_strerror(errno)));
        POSIXFileStream config_stream(config_fd);
        config_stream.write(config.data(), 0, config.size());

        hmac_fd = ::openat(folder_fd, CONFIG_HMAC_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (hmac_fd < 0)
            throw std::runtime_error(fmt::format(
                "Error creating {} for writing: {}", CONFIG_HMAC_FILE_NAME, sane_strerror(errno)));
        POSIXFileStream config_hmac_stream(hmac_fd);
        config_hmac_stream.write(hmac, 0, sizeof(hmac));

        operations::FileSystem fs(folder_fd, master_key, 0);
        auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
        root->set_uid(getuid());
        root->set_gid(getgid());
        root->set_mode(S_IFDIR | 0755);
        root->set_nlink(1);
        root->flush();
        return 0;
    }
    catch (...)
    {
        if (config_fd >= 0)
            ::unlinkat(folder_fd, CONFIG_FILE_NAME, 0);
        if (hmac_fd >= 0)
            ::unlinkat(folder_fd, CONFIG_HMAC_FILE_NAME, 0);
        throw;
    }
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

std::shared_ptr<securefs::Logger>
init_logger(const command_args& args, const void* password, size_t pass_len)
{
    if (args.no_log)
        return {};

    if (args.log_to_stderr)
        return std::make_shared<securefs::FileLogger>(securefs::LoggingLevel::WARN, stderr);

    auto create_salsa20_logger = [password, pass_len](const std::string& filename)
    {
        int fd = ::open(filename.c_str(), O_RDWR | O_CREAT, 0644);
        if (fd < 0)
            throw std::runtime_error(fmt::format(
                "Error creating log file {}: {}", filename, securefs::sane_strerror(errno)));
        auto ps_stream = std::make_shared<securefs::POSIXFileStream>(fd);
        return std::make_shared<securefs::StreamLogger>(
            securefs::LoggingLevel::WARN,
            securefs::make_stream_salsa20(std::move(ps_stream), password, pass_len));
    };

    if (!args.log_filename.empty())
        return create_salsa20_logger(args.log_filename);

    const char* home_dir = getenv("HOME");
    if (!home_dir)
        throw std::runtime_error("Error locating HOME directory");

    int home_fd = ::open(home_dir, O_RDONLY);
    if (home_fd < 0)
        throw std::runtime_error(
            fmt::format("Error opening {}: {}", home_dir, securefs::sane_strerror(errno)));
    securefs::FileDescriptorGuard guard(home_fd);

    securefs::ensure_directory(home_fd, ".local", 0700);
    securefs::ensure_directory(home_fd, ".local/securefs", 0700);
    securefs::ensure_directory(home_fd, ".local/securefs/logs", 0700);

    return create_salsa20_logger(fmt::format("{}/.local/securefs/logs/{}-pid{}.log",
                                             home_dir,
                                             securefs::format_current_time(),
                                             getpid()));
}

int mount_filesys(const command_args& args)
{
    using namespace securefs;
    int folder_fd = ::open(args.underlying_path.c_str(), O_RDONLY);
    if (folder_fd < 0)
        throw std::runtime_error(fmt::format(
            "Error opening directory {}: {}", args.underlying_path, sane_strerror(errno)));
    lock_base_directory(folder_fd);

    auto config_json = read_config(folder_fd);
    key_type master_key;

    CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
    size_t pass_len = 0;
    if (args.stdinpass)
        pass_len = insecure_read_password(stdin, nullptr, password.data(), password.size());
    else
        pass_len = try_read_password(password.data(), password.size());

    if (!parse_config(config_json, password, pass_len, master_key))
        throw std::runtime_error("Error: wrong password");

    if (!args.no_check)
    {
        byte hmac[CONFIG_MAC_LENGTH];
        read_hmac(folder_fd, hmac, sizeof(hmac));
        auto config_string = config_json.dump();
        if (!hmac_sha256_verify(config_string.data(),
                                config_string.size(),
                                master_key.data(),
                                master_key.size(),
                                hmac,
                                sizeof(hmac)))
            throw std::runtime_error("Error: HMAC mismatch for the configuration file");
    }

    unsigned flags = 0;
    if (args.readonly)
        flags |= FileTable::READ_ONLY;
    if (args.no_check)
        flags |= FileTable::NO_AUTHENTICATION;

    std::unique_ptr<securefs::operations::FileSystem> fs(
        new securefs::operations::FileSystem(folder_fd, master_key, flags));
    fs->logger = init_logger(args, password, pass_len);

    struct fuse_operations opt;
    init_fuse_operations(args.underlying_path.c_str(), opt);

    std::vector<const char*> fuse_args;
    fuse_args.push_back("securefs");
    if (args.foreground)
        fuse_args.push_back("-f");
    if (args.single_threaded)
        fuse_args.push_back("-s");
    if (args.debug)
        fuse_args.push_back("-d");
    if (args.readonly)
        fuse_args.push_back("-r");
    fuse_args.push_back(args.mount_point.c_str());

    return fuse_main(static_cast<int>(fuse_args.size()),
                     const_cast<char**>(fuse_args.data()),
                     &opt,
                     fs.release());
}

int viewlog_filesys(const command_args& args)
{
    using namespace securefs;
    CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
    size_t pass_len = 0;
    if (args.stdinpass)
        pass_len = insecure_read_password(stdin, nullptr, password.data(), password.size());
    else
        pass_len = try_read_password(password.data(), password.size());

    int fd = ::open(args.log_filename.c_str(), O_RDONLY);
    if (fd < 0)
        throw std::runtime_error(
            fmt::format("Error opening log file {}: {}", args.log_filename, sane_strerror(errno)));

    auto stream = make_stream_salsa20(std::make_shared<POSIXFileStream>(fd), password, pass_len);
    byte buffer[4096];
    length_type off = 0;
    while (true)
    {
        auto len = stream->read(buffer, off, sizeof(buffer));
        if (len == 0)
            break;
        fwrite(buffer, 1, len, stdout);
        off += len;
    }
    fflush(stdout);
    return 0;
}
}

namespace securefs
{
int commands_main(int argc, char** argv)
{
    try
    {
        command_args args;
        parse_args(argc, argv, args);
        if (!args.action)
        {
            fprintf(stderr, "Action not implemented\n");
            return -1;
        }
        return args.action(args);
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
