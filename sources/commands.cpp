#include "commands.h"
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
}

namespace securefs
{

std::shared_ptr<FileStream> CommandBase::open_config_stream(const std::string& path, int flags)
{
    FileSystemService service;
    return service.open_file_stream(path, flags, 0644);
}

FSConfig CommandBase::read_config(StreamBase* stream, const void* password, size_t pass_len)
{
    FSConfig result;

    std::string str(stream->size(), 0);
    stream->read(&str[0], 0, str.size());
    Json::Reader reader;
    Json::Value value;
    if (!reader.parse(str, value))
        throw std::runtime_error(fmt::format("Failure to parse the config file: {}",
                                             reader.getFormattedErrorMessages()));

    if (!parse_config(
            value, password, pass_len, result.master_key, result.block_size, result.iv_size))
        throw std::runtime_error("Invalid password");
    result.version = value["version"].asUInt();
    return result;
}

void CommandBase::write_config(StreamBase* stream,
                               const FSConfig& config,
                               const void* password,
                               size_t pass_len,
                               unsigned rounds)
{
    key_type salt;
    generate_random(salt.data(), salt.size());
    auto str = generate_config(config.version,
                               config.master_key,
                               salt,
                               password,
                               pass_len,
                               config.block_size,
                               config.iv_size,
                               rounds)
                   .toStyledString();
    stream->write(str.data(), 0, str.size());
}

class CommonCommandBase : public CommandBase
{
protected:
    TCLAP::UnlabeledValueArg<std::string> data_dir{
        "dir", "Directory where the data are stored", true, "", "data_dir"};
    TCLAP::ValueArg<std::string> config_path{
        "",
        "config",
        "Full path name of the config file. ${data_dir}/.securefs.json by default",
        false,
        "",
        "config_path"};
    TCLAP::ValueArg<std::string> pass{
        "",
        "pass",
        "Password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "password"};

protected:
    std::string get_real_config_path()
    {
        return config_path.isSet() ? config_path.getValue()
                                   : data_dir.getValue() + '/' + CONFIG_FILE_NAME;
    }
};

class CreateCommand : public CommonCommandBase
{
private:
    CryptoPP::AlignedSecByteBlock password;

    TCLAP::SwitchArg stdinpass{
        "s", "stdinpass", "Read password from stdin directly (useful for piping)"};
    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of PBKDF2 are applied (0 for automatic)",
        false,
        0,
        "integer"};
    TCLAP::ValueArg<unsigned int> version{
        "", "ver", "The format version (1 or 2)", false, 2, "integer"};
    TCLAP::ValueArg<unsigned int> iv_size{
        "", "iv-size", "The IV size (ignored for fs format 1)", false, 12, "integer"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&iv_size);
        cmdline.add(&stdinpass);
        cmdline.add(&rounds);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.add(&version);
        cmdline.add(&pass);
        cmdline.parse(argc, argv);

        if (pass.isSet())
        {
            password.resize(pass.getValue().size());
            memcpy(password.data(), pass.getValue().data(), password.size());
            return;
        }

        password.resize(MAX_PASS_LEN);
        if (stdinpass.getValue())
        {
            password.resize(
                insecure_read_password(stdin, nullptr, password.data(), password.size()));
        }
        else
        {
            password.resize(try_read_password_with_confirmation(password.data(), password.size()));
        }
    }

    int execute() override
    {
        FSConfig config;
        config.iv_size = iv_size.getValue();
        config.version = version.getValue();
        config.block_size = 4096;

        auto config_stream
            = open_config_stream(get_real_config_path(), O_WRONLY | O_CREAT | O_EXCL);

        write_config(
            config_stream.get(), config, password.data(), password.size(), rounds.getValue());
        config_stream.reset();

        operations::FSOptions opt;
        opt.version = version.getValue();
        opt.root = std::make_shared<FileSystemService>(data_dir.getValue());
        opt.master_key = config.master_key;
        opt.flags = 0;
        opt.block_size = 4096;
        opt.iv_size = version.getValue() == 1 ? 32 : iv_size.getValue();

        operations::FileSystem fs(opt);
        auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
        root->set_uid(securefs::FileSystemService::getuid());
        root->set_gid(securefs::FileSystemService::getgid());
        root->set_mode(S_IFDIR | 0755);
        root->set_nlink(1);
        root->flush();
        return 0;
    }

    const char* long_name() const noexcept override { return "create"; }

    char short_name() const noexcept override { return 'c'; }

    const char* help_message() const noexcept override { return "Create a new filesystem"; }
};

class ChangePasswordCommand : public CommonCommandBase
{
private:
    CryptoPP::AlignedSecByteBlock old_password, new_password;
    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of PBKDF2 are applied (0 for automatic)",
        false,
        0,
        "integer"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&rounds);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.parse(argc, argv);
        old_password.resize(MAX_PASS_LEN);
        old_password.resize(try_read_password(old_password.data(), old_password.size()));

        fputs("\nNow enter new password\n", stderr);
        new_password.resize(MAX_PASS_LEN);
        new_password.resize(
            try_read_password_with_confirmation(new_password.data(), new_password.size()));
    }

    int execute() override
    {
        FileSystemService service;
        auto original_path = get_real_config_path();
        byte buffer[16];
        auto tmp_path = original_path + hexify(buffer, sizeof(buffer));
        auto stream = service.open_file_stream(original_path, O_RDONLY, 0644);
        auto config = read_config(stream.get(), old_password.data(), old_password.size());
        stream = service.open_file_stream(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        write_config(
            stream.get(), config, new_password.data(), new_password.size(), rounds.getValue());
        stream.reset();
        service.rename(tmp_path, original_path);
        return 0;
    }

    const char* long_name() const noexcept override { return "chpass"; }

    char short_name() const noexcept override { return 0; }

    const char* help_message() const noexcept override
    {
        return "Change password of existing filesystem";
    }
};

class MountCommand : public CommonCommandBase
{
private:
    CryptoPP::AlignedSecByteBlock password;
    TCLAP::SwitchArg stdinpass{
        "s", "stdinpass", "Read password from stdin directly (useful for piping)"};
    TCLAP::SwitchArg background{"b", "background", "Run securefs in the background"};
    TCLAP::SwitchArg insecure{
        "i", "insecure", "Disable all integrity verification (insecure mode)"};
    TCLAP::SwitchArg noxattr{"x", "noxattr", "Disable built-in xattr support"};
    TCLAP::SwitchArg trace{"", "trace", "Trace all calls into `securefs`"};
    TCLAP::ValueArg<std::string> log{
        "", "log", "Path of the log file (may contain sensitive information)", false, "", "path"};

    TCLAP::UnlabeledValueArg<std::string> mount_point{
        "mount_point", "Mount point", true, "", "mount_point"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());

#ifdef __APPLE__
        cmdline.add(&noxattr);
#endif

        cmdline.add(&stdinpass);
        cmdline.add(&background);
        cmdline.add(&insecure);
        cmdline.add(&trace);
        cmdline.add(&log);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.add(&mount_point);
        cmdline.add(&pass);
        cmdline.parse(argc, argv);

        if (pass.isSet())
        {
            password.resize(pass.getValue().size());
            memcpy(password.data(), pass.getValue().data(), password.size());
            generate_random(&pass.getValue()[0], pass.getValue().size());
            return;
        }

        password.resize(MAX_PASS_LEN);
        if (stdinpass.getValue())
        {
            password.resize(
                insecure_read_password(stdin, nullptr, password.data(), password.size()));
        }
        else
        {
            password.resize(try_read_password(password.data(), password.size()));
        }
    }

    int execute() override
    {
        if (!securefs::FileSystemService::raise_fd_limit())
        {
            fputs("Warning: failure to raise the maximum file descriptor limit\n", stderr);
        }

        auto config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        auto config = read_config(config_stream.get(), password.data(), password.size());
        config_stream.reset();

        generate_random(password.data(), password.size());    // Erase user input

        operations::FSOptions fsopt;
        fsopt.root = std::make_shared<FileSystemService>(data_dir.getValue());
        fsopt.root->lock();
        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        fsopt.master_key = config.master_key;
        fsopt.flags = 0;
        if (insecure.getValue())
            fsopt.flags.get() |= FileTable::NO_AUTHENTICATION;

        if (log.isSet())
        {
            FILE* fp = fopen(log.getValue().c_str(), "ab");
            if (!fp)
            {
                fmt::print(
                    stderr, "Failed to open file {}: {}\n", log.getValue(), sane_strerror(errno));
                return 10;
            }
            fsopt.logger = std::make_shared<Logger>(LoggingLevel::Warn, fp, true);
        }
        else if (!background.getValue())
        {
            fsopt.logger = std::make_shared<Logger>(LoggingLevel::Warn, stderr, false);
        }

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

    const char* long_name() const noexcept override { return "mount"; }

    char short_name() const noexcept override { return 'm'; }

    const char* help_message() const noexcept override { return "Mount an existing filesystem"; }
};

class FixCommand : public CommonCommandBase
{
private:
    CryptoPP::AlignedSecByteBlock password;
    TCLAP::SwitchArg stdinpass{
        "s", "stdinpass", "Read password from stdin directly (useful for piping)"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&stdinpass);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.parse(argc, argv);

        password.resize(MAX_PASS_LEN);
        if (stdinpass.getValue())
        {
            password.resize(
                insecure_read_password(stdin, nullptr, password.data(), password.size()));
        }
        else
        {
            password.resize(try_read_password(password.data(), password.size()));
        }
    }

    int execute() override
    {
#ifdef _WIN32
        fputs("Sorry, not implemented on Windows\n", stderr);
        return 13;
#else
        auto config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        auto config = read_config(config_stream.get(), password.data(), password.size());
        config_stream.reset();

        generate_random(password.data(), password.size());    // Erase user input

        operations::FSOptions fsopt;
        fsopt.root = std::make_shared<FileSystemService>(data_dir.getValue());
        fsopt.root->lock();
        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        fsopt.master_key = config.master_key;
        fsopt.flags = 0;

        operations::FileSystem fs(fsopt);
        fix(data_dir.getValue(), &fs);
        return 0;
#endif
    }

    const char* long_name() const noexcept override { return "fix"; }

    char short_name() const noexcept override { return 0; }

    const char* help_message() const noexcept override
    {
        return "Try to fix errors in an existing filesystem";
    }
};

class TestCommand : public CommandBase
{
private:
    int m_argc;
    const char* const* m_argv;

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        m_argc = argc;
        m_argv = argv;
    }

    int execute() override
    {
        int test_main(int argc, const char* const* argv);
        return test_main(m_argc, m_argv);
    }

    const char* long_name() const noexcept override { return "test"; }

    char short_name() const noexcept override { return 0; }

    const char* help_message() const noexcept override { return "Do a test of the program"; }
};

std::string process_name;

int commands_main(int argc, const char* const* argv)
{
    try
    {
        std::vector<std::unique_ptr<CommandBase>> cmds;
        cmds.reserve(5);
        cmds.push_back(make_unique<MountCommand>());
        cmds.push_back(make_unique<CreateCommand>());
        cmds.push_back(make_unique<ChangePasswordCommand>());
        cmds.push_back(make_unique<FixCommand>());
        cmds.push_back(make_unique<TestCommand>());

        auto print_usage = [&]() {
            fputs("Available subcommands:\n\n", stderr);

            for (auto&& command : cmds)
            {
                if (command->short_name())
                {
                    fmt::print(stderr,
                               "{} (alias: {}): {}\n",
                               command->long_name(),
                               command->short_name(),
                               command->help_message());
                }
                else
                {
                    fmt::print(stderr, "{}: {}\n", command->long_name(), command->help_message());
                }
            }

            fmt::print(stderr, "\nType {} ${{SUBCOMMAND}} --help for details\n", argv[0]);
            return 1;
        };

        if (argc < 2)
            return print_usage();
        argc--;
        argv++;

        for (std::unique_ptr<CommandBase>& command : cmds)
        {
            if (strcmp(argv[0], command->long_name()) == 0
                || (argv[0] != 0 && argv[0][0] == command->short_name() && argv[0][1] == 0))
            {
                command->parse_cmdline(argc, argv);
                return command->execute();
            }
        }
        return print_usage();
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

int main(int argc, char** argv)
{
    process_name = argv[0];
    return commands_main(argc, argv);
}
