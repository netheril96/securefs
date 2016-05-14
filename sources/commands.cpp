#include "exceptions.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"
#include "streams.h"

#include <cryptopp/secblock.h>
#include <format.h>
#include <fuse.h>
#include <json/json.h>
#include <tclap/CmdLine.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string.h>
#include <typeinfo>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

using namespace securefs;

namespace
{

static const char* VERSION_HEADER = "version=1";
static const std::string CONFIG_FILE_NAME = ".securefs.json";
static const std::string CONFIG_TMP_FILE_NAME = ".securefs.json.tmp";
static const unsigned MIN_ITERATIONS = 20000;
static const unsigned MIN_DERIVE_SECONDS = 1;
static const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;
static const size_t MAX_PASS_LEN = 4000;

#ifndef _WIN32

enum class NLinkFixPhase
{
    CollectingNLink,
    FixingNLink
};

void fix_hardlink_count(operations::FileSystem* fs,
                        Directory* dir,
                        std::unordered_map<id_type, int, id_hash>* nlink_map,
                        NLinkFixPhase phase)
{
    std::vector<std::pair<id_type, int>> listings;
    dir->iterate_over_entries([&listings](const std::string&, const id_type& id, int type) {
        listings.emplace_back(id, type);
        return true;
    });

    for (auto&& entry : listings)
    {
        id_type& id = std::get<0>(entry);
        int type = std::get<1>(entry);

        AutoClosedFileBase base(nullptr, nullptr);
        try
        {
            base = open_as(fs->table, id, FileBase::BASE);
        }
        catch (...)
        {
            continue;
        }
        switch (phase)
        {
        case NLinkFixPhase::FixingNLink:
            base->set_nlink(nlink_map->at(id));
            break;

        case NLinkFixPhase::CollectingNLink:
            nlink_map->operator[](id)++;
            break;

        default:
            UNREACHABLE();
        }
        base.reset(nullptr);
        if (type == FileBase::DIRECTORY)
        {
            fix_hardlink_count(
                fs, open_as(fs->table, id, type).get_as<Directory>(), nlink_map, phase);
        }
    }
}

void fix_helper(operations::FileSystem* fs,
                Directory* dir,
                const std::string& dir_name,
                std::unordered_set<id_type, id_hash>* all_ids)
{
    std::vector<std::tuple<std::string, id_type, int>> listings;
    dir->iterate_over_entries([&listings](const std::string& name, const id_type& id, int type) {
        listings.emplace_back(name, id, type);
        return true;
    });

    for (auto&& entry : listings)
    {
        const std::string& name = std::get<0>(entry);
        id_type& id = std::get<1>(entry);
        int type = std::get<2>(entry);

        AutoClosedFileBase base(nullptr, nullptr);
        try
        {
            base = open_as(fs->table, id, FileBase::BASE);
        }
        catch (const std::exception& e)
        {
            fprintf(stderr,
                    "Encounter exception when opening %s: %s\nDo you want to remove the entry? "
                    "(Yes/No, default: no)\n",
                    (dir_name + '/' + name).c_str(),
                    e.what());
            auto remove = [&]() { dir->remove_entry(name, id, type); };
            auto ignore = []() {};
            respond_to_user_action({{"\n", ignore},
                                    {"y\n", remove},
                                    {"yes\n", remove},
                                    {"n\n", ignore},
                                    {"no\n", ignore}});
            continue;
        }

        int real_type = base->get_real_type();
        if (type != real_type)
        {
            printf("Mismatch type for %s (inode has type %s, directory entry has type %s). Do you "
                   "want to fix it? (Yes/No default: yes)\n",
                   (dir_name + '/' + name).c_str(),
                   FileBase::type_name(real_type),
                   FileBase::type_name(type));
            fflush(stdout);

            auto fix_type = [&]() {
                dir->remove_entry(name, id, type);
                dir->add_entry(name, id, real_type);
            };

            auto ignore = []() {};

            respond_to_user_action({{"\n", fix_type},
                                    {"y\n", fix_type},
                                    {"yes\n", fix_type},
                                    {"n\n", ignore},
                                    {"no\n", ignore}});
        }
        all_ids->insert(id);
        base.reset(nullptr);

        if (real_type == FileBase::DIRECTORY)
        {
            fix_helper(fs,
                       open_as(fs->table, id, FileBase::DIRECTORY).get_as<Directory>(),
                       dir_name + '/' + name,
                       all_ids);
        }
    }
}

void fix(const std::string& basedir, operations::FileSystem* fs)
{
    std::unordered_set<id_type, id_hash> all_ids{fs->root_id};
    AutoClosedFileBase root_dir = open_as(fs->table, fs->root_id, FileBase::DIRECTORY);
    fix_helper(fs, root_dir.get_as<Directory>(), "", &all_ids);
    auto all_underlying_ids = find_all_ids(basedir);

    for (const id_type& id : all_underlying_ids)
    {
        if (all_ids.find(id) == all_ids.end())
        {
            printf("%s is not referenced anywhere in the filesystem, do you want to recover it? "
                   "([r]ecover/[d]elete/[i]gnore default: recover)\n",
                   hexify(id).c_str());
            fflush(stdout);

            auto recover = [&]() {
                auto base = open_as(fs->table, id, FileBase::BASE);
                root_dir.get_as<Directory>()->add_entry(hexify(id), id, base->get_real_type());
            };

            auto remove = [&]() {
                FileBase* base = fs->table.open_as(id, FileBase::BASE);
                int real_type = base->get_real_type();
                fs->table.close(base);
                auto real_file_handle = open_as(fs->table, id, real_type);
                real_file_handle->unlink();
            };

            auto ignore = []() {};

            respond_to_user_action({{"\n", recover},
                                    {"r\n", recover},
                                    {"recover\n", recover},
                                    {"i\n", ignore},
                                    {"ignore\n", ignore},
                                    {"d\n", remove},
                                    {"delete\n", remove}});
        }
    }

    std::unordered_map<id_type, int, id_hash> nlink_map;
    puts("Fixing hardlink count ...");
    fix_hardlink_count(
        fs, root_dir.get_as<Directory>(), &nlink_map, NLinkFixPhase::CollectingNLink);
    fix_hardlink_count(fs, root_dir.get_as<Directory>(), &nlink_map, NLinkFixPhase::FixingNLink);
    puts("Fix complete");
}
#endif

Json::Value generate_config(int version,
                            const securefs::key_type& master_key,
                            const securefs::key_type& salt,
                            const void* password,
                            size_t pass_len,
                            unsigned block_size,
                            unsigned iv_size,
                            unsigned rounds = 0)
{
    Json::Value config;
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

    Json::Value encrypted_key;
    encrypted_key["IV"] = securefs::hexify(iv, sizeof(iv));
    encrypted_key["MAC"] = securefs::hexify(mac, sizeof(mac));
    encrypted_key["key"] = securefs::hexify(encrypted_master_key);

    config["encrypted_key"] = std::move(encrypted_key);

    if (version == 2)
    {
        config["block_size"] = block_size;
        config["iv_size"] = iv_size;
    }
    return config;
}

bool parse_config(const Json::Value& config,
                  const void* password,
                  size_t pass_len,
                  securefs::key_type& master_key,
                  unsigned& block_size,
                  unsigned& iv_size)
{
    using namespace securefs;
    unsigned version = config["version"].asUInt();

    if (version == 1)
    {
        block_size = 4096;
        iv_size = 32;
    }
    else if (version == 2)
    {
        block_size = config["block_size"].asUInt();
        iv_size = config["iv_size"].asUInt();
    }
    else
    {
        throw InvalidArgumentException(fmt::format("Unsupported version {}", version));
    }

    unsigned iterations = config["iterations"].asUInt();

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt, encrypted_key, key_to_encrypt_master_key;

    std::string salt_hex = config["salt"].asString();
    auto&& encrypted_key_json_value = config["encrypted_key"];
    std::string iv_hex = encrypted_key_json_value["IV"].asString();
    std::string mac_hex = encrypted_key_json_value["MAC"].asString();
    std::string ekey_hex = encrypted_key_json_value["key"].asString();

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

Json::Value read_config(FileSystemService& dir)
{
    using namespace securefs;
    auto config_stream = dir.open_file_stream(CONFIG_FILE_NAME, O_RDONLY, 0);
    std::string config_str(config_stream->size(), 0);
    if (config_str.empty())
        throw std::runtime_error("Error parsing config file: file is empty");

    config_stream->read(&config_str[0], 0, config_str.size());
    Json::Reader reader;
    Json::Value result;
    if (!reader.parse(config_str, result))
        throw std::runtime_error(fmt::format("Failure to parse the config file: {}",
                                             reader.getFormattedErrorMessages()));
    return result;
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
    TCLAP::ValueArg<int> version("", "ver", "The format version (1 or 2)", false, 2, "integer");
    TCLAP::ValueArg<int> iv_size(
        "", "iv-size", "The IV size (ignored for fs format 1)", false, 12, "integer");

    cmdline.add(&iv_size);
    cmdline.add(&stdinpass);
    cmdline.add(&rounds);
    cmdline.add(&dir);
    cmdline.add(&version);
    cmdline.parse(argc, argv);

    if (version.getValue() != 1 && version.getValue() != 2)
    {
        throw std::runtime_error("Unknown format version");
    }

    if (iv_size.getValue() < 12 || iv_size.getValue() > 64)
        throw std::runtime_error("Invalid IV size");

    auto root = std::make_shared<FileSystemService>(dir.getValue());
    root->lock();

    std::shared_ptr<FileStream> config_stream;

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

        auto config = generate_config(version.getValue(),
                                      master_key,
                                      salt,
                                      password.data(),
                                      pass_len,
                                      4096,
                                      iv_size.getValue(),
                                      rounds.getValue())
                          .toStyledString();

        config_stream = root->open_file_stream(CONFIG_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
        config_stream->write(config.data(), 0, config.size());

        operations::FSOptions opt;
        opt.version = version.getValue();
        opt.root = root;
        opt.master_key = master_key;
        opt.flags = 0;
        opt.block_size = 4096;
        opt.iv_size = version.getValue() == 1 ? 32 : 12;
        operations::FileSystem fs(opt);
        auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
        root->set_uid(securefs::FileSystemService::getuid());
        root->set_gid(securefs::FileSystemService::getgid());
        root->set_mode(S_IFDIR | 0755);
        root->set_nlink(1);
        root->flush();
        fputs("Filesystem successfully created\n", stderr);
        return 0;
    }
    catch (...)
    {
        if (config_stream)
        {
            config_stream.reset();
            root->remove_file(CONFIG_FILE_NAME);
        }
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
    opt.statfs = &securefs::operations::statfs;

    (void)xattr;

#ifdef __APPLE__
    if (!xattr)
        return;
    auto rc = ::listxattr(underlying_path, nullptr, 0, 0);
    if (rc < 0)
    {
        fprintf(stderr,
                "Warning: %s has no extended attribute support.\nXattr is disabled\n",
                underlying_path);
        return;    // The underlying filesystem does not support extended attributes
    }
    opt.listxattr = &securefs::operations::listxattr;
    opt.getxattr = &securefs::operations::getxattr;
    opt.setxattr = &securefs::operations::setxattr;
    opt.removexattr = &securefs::operations::removexattr;
#endif
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

operations::FSOptions
get_options(const std::string& data_dir, bool stdinpass, bool insecure, const std::string& logfile)
{
    operations::FSOptions fsopt;
    fsopt.root = std::make_shared<FileSystemService>(data_dir);
    fsopt.root->lock();

    auto config_json = read_config(*fsopt.root);
    auto version = config_json["version"].asUInt();
    fsopt.version = version;
    if (version != 1 && version != 2)
        throw std::runtime_error(fmt::format("Unkown format version {}", version));

    {
        CryptoPP::AlignedSecByteBlock password(MAX_PASS_LEN);
        size_t pass_len = 0;
        if (stdinpass)
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

    if (!logfile.empty())
        fsopt.logger
            = std::make_shared<FileLogger>(LoggingLevel::Warn, fopen(logfile.c_str(), "w+b"));
    else
        fsopt.logger = std::make_shared<FileLogger>(LoggingLevel::Warn, stderr);

    fsopt.flags = 0;
    if (insecure)
        fsopt.flags.get() |= FileTable::NO_AUTHENTICATION;
    return fsopt;
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
    TCLAP::SwitchArg trace("", "trace", "Trace all calls into `securefs`");
    TCLAP::ValueArg<std::string> log(
        "", "log", "Path of the log file (may contain sensitive information)", false, "", "path");

    TCLAP::UnlabeledValueArg<std::string> data_dir(
        "data_dir", "Directory where the data are stored", true, "", "directory");
    TCLAP::UnlabeledValueArg<std::string> mount_point(
        "mount_point", "Mount point", true, "", "directory");

#ifdef __APPLE__
    cmdline.add(&noxattr);
#endif

    cmdline.add(&stdinpass);
    cmdline.add(&background);
    cmdline.add(&insecure);
    cmdline.add(&trace);
    cmdline.add(&log);
    cmdline.add(&data_dir);
    cmdline.add(&mount_point);
    cmdline.parse(argc, argv);

    if (!securefs::FileSystemService::raise_fd_limit())
    {
        fputs("Warning: failure to raise the maximum file descriptor limit\n", stderr);
    }

    operations::FSOptions fsopt = get_options(
        data_dir.getValue(), stdinpass.getValue(), insecure.getValue(), log.getValue());

    if (trace.getValue() && fsopt.logger)
        fsopt.logger->set_level(LoggingLevel::Debug);

    fprintf(stderr,
            "Mounting filesystem stored at %s onto %s\nFormat version: %u\n",
            data_dir.getValue().c_str(),
            mount_point.getValue().c_str(),
            fsopt.version.get());

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

int fix_filesys(int argc, char** argv)
{
    TCLAP::CmdLine cmdline("Trying to fix corruptions in the underlying storage");
    TCLAP::UnlabeledValueArg<std::string> dir(
        "dir", "Directory where the data are stored", true, "", "directory");
    cmdline.add(&dir);
    cmdline.parse(argc, argv);

#ifndef _WIN32
    operations::FileSystem fs(get_options(dir.getValue(), false, false, ""));
    fix(dir.getValue(), &fs);
    return 0;
#else
    fprintf(stderr, "Sorry, this functionality is not implemented on Windows for now");
    return 9;
#endif
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

    FileSystemService root(dir.getValue());
    root.lock();

    auto config_json = read_config(root);
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
    auto config = generate_config(config_json["version"].asUInt(),
                                  master_key,
                                  salt,
                                  password.data(),
                                  pass_len,
                                  block_size,
                                  iv_size,
                                  rounds.getValue())
                      .toStyledString();

    auto config_stream
        = root.open_file_stream(CONFIG_TMP_FILE_NAME, O_WRONLY | O_CREAT | O_EXCL, 0644);
    config_stream->write(config.data(), 0, config.size());
    config_stream.reset();

    root.rename(CONFIG_TMP_FILE_NAME, CONFIG_FILE_NAME);
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
       {nullptr, "chpass", "Change the password of existing filesystem", &chpass_filesys},
       {nullptr, "fix", "Trying to fix the underlying storage", &fix_filesys}};

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
