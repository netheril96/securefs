#include "commands.h"
#include "exceptions.h"
#include "lite_operations.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"
#include "streams.h"

#include <cryptopp/cpu.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <fuse.h>
#include <json/json.h>
#include <tclap/CmdLine.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>
#include <typeinfo>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include <fcntl.h>

#ifdef __APPLE__

#include <sys/xattr.h>

#endif

using namespace securefs;

namespace
{

static const std::string CONFIG_FILE_NAME = ".securefs.json";
static const unsigned MIN_ITERATIONS = 20000;
static const unsigned MIN_DERIVE_SECONDS = 1;
static const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;
static const size_t MAX_PASS_LEN = 4000;

static const char* get_version_header(unsigned version)
{
    switch (version)
    {
    case 1:
    case 2:
    case 3:
        return "version=1";    // These headers are all the same for backwards compatible behavior
                               // with old mistakes
    case 4:
        return "version=4";
    default:
        throwInvalidArgumentException("Unknown format version");
    }
}

enum class NLinkFixPhase
{
    CollectingNLink,
    FixingNLink
};

void fix_hardlink_count(operations::FileSystemContext* fs,
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

void fix_helper(operations::FileSystemContext* fs,
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

void fix(const std::string& basedir, operations::FileSystemContext* fs)
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

Json::Value generate_config(unsigned int version,
                            const CryptoPP::AlignedSecByteBlock& master_key,
                            const securefs::key_type& salt,
                            const void* password,
                            size_t pass_len,
                            unsigned block_size,
                            unsigned iv_size,
                            unsigned rounds = 0)
{
    Json::Value config;
    config["version"] = version;
    securefs::key_type key_to_encrypt;
    CryptoPP::AlignedSecByteBlock encrypted_master_key(nullptr, master_key.size());

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
                              get_version_header(version),
                              strlen(get_version_header(version)),
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

    if (version >= 2)
    {
        config["block_size"] = block_size;
        config["iv_size"] = iv_size;
    }
    return config;
}

bool parse_config(const Json::Value& config,
                  const void* password,
                  size_t pass_len,
                  CryptoPP::AlignedSecByteBlock& master_key,
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
    else if (version == 2 || version == 3 || version == 4)
    {
        block_size = config["block_size"].asUInt();
        iv_size = config["iv_size"].asUInt();
    }
    else
    {
        throwInvalidArgumentException(strprintf("Unsupported version %u", version));
    }

    unsigned iterations = config["iterations"].asUInt();

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt, key_to_encrypt_master_key;
    CryptoPP::AlignedSecByteBlock encrypted_key;

    std::string salt_hex = config["salt"].asString();
    auto&& encrypted_key_json_value = config["encrypted_key"];
    std::string iv_hex = encrypted_key_json_value["IV"].asString();
    std::string mac_hex = encrypted_key_json_value["MAC"].asString();
    std::string ekey_hex = encrypted_key_json_value["key"].asString();

    parse_hex(salt_hex, salt.data(), salt.size());
    parse_hex(iv_hex, iv, sizeof(iv));
    parse_hex(mac_hex, mac, sizeof(mac));

    encrypted_key.resize(ekey_hex.size() / 2);
    parse_hex(ekey_hex, encrypted_key.data(), encrypted_key.size());
    master_key.resize(encrypted_key.size());

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
                           get_version_header(version),
                           strlen(get_version_header(version)),
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
    return OSService::get_default().open_file_stream(path, flags, 0644);
}

FSConfig CommandBase::read_config(StreamBase* stream, const void* password, size_t pass_len)
{
    FSConfig result;

    std::string str(stream->size(), 0);
    stream->read(&str[0], 0, str.size());
    Json::Reader reader;
    Json::Value value;
    if (!reader.parse(str, value))
        throw std::runtime_error(strprintf("Failure to parse the config file: %s",
                                           reader.getFormattedErrorMessages().c_str()));

    if (!parse_config(
            value, password, pass_len, result.master_key, result.block_size, result.iv_size))
        throw std::runtime_error("Invalid password");
    result.version = value["version"].asUInt();
    return result;
}

static void copy_key(const CryptoPP::AlignedSecByteBlock& in_key, key_type* out_key)
{
    if (in_key.size() != out_key->size())
        throw std::runtime_error("Invalid key size");
    memcpy(out_key->data(), in_key.data(), out_key->size());
}

static void copy_key(const CryptoPP::AlignedSecByteBlock& in_key, optional<key_type>* out_key)
{
    out_key->emplace();
    copy_key(in_key, &(out_key->value()));
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
        "s", "stdinpass", "Compatibility flag with older version. Does nothing."};
    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of PBKDF2 are applied (0 for automatic)",
        false,
        0,
        "integer"};
    TCLAP::ValueArg<unsigned int> format{
        "", "format", "The filesystem format version (1,2,3)", false, 4, "integer"};
    TCLAP::ValueArg<unsigned int> iv_size{
        "", "iv-size", "The IV size (ignored for fs format 1)", false, 12, "integer"};
    TCLAP::ValueArg<unsigned int> block_size{
        "", "block-size", "Block size for files (ignored for fs format 1)", false, 4096, "integer"};
    TCLAP::SwitchArg store_time{
        "",
        "store_time",
        "alias for \"--format 3\", enables the extension where timestamp are stored and encrypted"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&iv_size);
        cmdline.add(&stdinpass);
        cmdline.add(&rounds);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.add(&format);
        cmdline.add(&pass);
        cmdline.add(&store_time);
        cmdline.add(&block_size);
        cmdline.parse(argc, argv);

        if (pass.isSet())
        {
            password.resize(pass.getValue().size());
            memcpy(password.data(), pass.getValue().data(), password.size());
            return;
        }

        password.resize(MAX_PASS_LEN);
        if (!OSService::isatty(0))
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
        if (format.isSet() && store_time.isSet())
        {
            fprintf(stderr, "Conflicting flags --format and --store_time are specified together\n");
            return 1;
        }

        if (format.isSet() && format.getValue() == 1 && (iv_size.isSet() || block_size.isSet()))
        {
            fprintf(stderr, "IV and block size options are not available for filesystem format 1");
            return 1;
        }

        unsigned format_version = store_time.isSet() ? 3 : format.getValue();

        OSService::get_default().ensure_directory(data_dir.getValue(), 0755);

        FSConfig config;
        config.master_key.resize(format_version < 4 ? KEY_LENGTH : 3 * KEY_LENGTH);
        CryptoPP::BlockingRng blockingRng;
        blockingRng.GenerateBlock(config.master_key.data(), config.master_key.size());

        config.iv_size = format_version == 1 ? 32 : iv_size.getValue();
        config.version = format_version;
        config.block_size = block_size.getValue();

        auto config_stream
            = open_config_stream(get_real_config_path(), O_WRONLY | O_CREAT | O_EXCL);
        write_config(
            config_stream.get(), config, password.data(), password.size(), rounds.getValue());
        config_stream.reset();

        if (format_version < 4)
        {
            operations::MountOptions opt;
            opt.version = format_version;
            opt.root = std::make_shared<OSService>(data_dir.getValue());
            copy_key(config.master_key, &opt.master_key);
            opt.flags = format_version < 3 ? 0 : FileTable::STORE_TIME;
            opt.block_size = config.block_size;
            opt.iv_size = config.iv_size;

            operations::FileSystemContext fs(opt);
            auto root = fs.table.create_as(fs.root_id, FileBase::DIRECTORY);
            root->set_uid(securefs::OSService::getuid());
            root->set_gid(securefs::OSService::getgid());
            root->set_mode(S_IFDIR | 0755);
            root->set_nlink(1);
            root->flush();
        }
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
        auto original_path = get_real_config_path();
        byte buffer[16];
        generate_random(buffer, sizeof(buffer));
        auto tmp_path = original_path + hexify(buffer, sizeof(buffer));
        auto stream = OSService::get_default().open_file_stream(original_path, O_RDONLY, 0644);
        auto config = read_config(stream.get(), old_password.data(), old_password.size());
        stream = OSService::get_default().open_file_stream(
            tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        write_config(
            stream.get(), config, new_password.data(), new_password.size(), rounds.getValue());
        stream.reset();
        OSService::get_default().rename(tmp_path, original_path);
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
    std::vector<byte> password;
    TCLAP::SwitchArg stdinpass{
        "s", "stdinpass", "Compatibility flag with older version. Does nothing."};
    TCLAP::SwitchArg background{"b", "background", "Run securefs in the background"};
    TCLAP::SwitchArg insecure{
        "i", "insecure", "Disable all integrity verification (insecure mode)"};
    TCLAP::SwitchArg noxattr{"x", "noxattr", "Disable built-in xattr support"};
    TCLAP::SwitchArg trace{"", "trace", "Trace all calls into `securefs` (implies --info)"};
    TCLAP::ValueArg<std::string> log{
        "", "log", "Path of the log file (may contain sensitive information)", false, "", "path"};
    TCLAP::MultiArg<std::string> fuse_options{
        "o",
        "opt",
        "Additional FUSE options; this may crash the filesystem; use only for testing!",
        false,
        "options"};
    TCLAP::ValueArg<unsigned> uid_override{
        "",
        "override-uid",
        "Override the owner UID of all files to this; allows bypass of "
        "the permission system",
        false,
        0,
        "uid"};
    TCLAP::ValueArg<unsigned> gid_override{
        "",
        "override-gid",
        "Override the owner GID of all files to this; allows bypass of "
        "the permission system",
        false,
        0,
        "gid"};
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
        cmdline.add(&fuse_options);
        cmdline.add(&uid_override);
        cmdline.add(&gid_override);
        cmdline.parse(argc, argv);

        if (pass.isSet() && !pass.getValue().empty())
        {
            password.resize(pass.getValue().size());
            memcpy(password.data(), pass.getValue().data(), password.size());
            generate_random(&pass.getValue()[0], pass.getValue().size());
            return;
        }

        password.resize(MAX_PASS_LEN);
        if (!OSService::isatty(0))
        {
            password.resize(
                insecure_read_password(stdin, nullptr, password.data(), password.size()));
        }
        else
        {
            password.resize(try_read_password(password.data(), password.size()));
        }
    }

    const char* get_tmp_dir()
    {
        const char* ret = getenv("TMP");
        if (ret)
            return ret;
        ret = getenv("TEMP");
        if (ret)
            return ret;
        ret = getenv("TMPDIR");
        if (ret)
            return ret;
        ret = getenv("TEMPDIR");
        if (ret)
            return ret;
        return "/tmp";
    }

    void recreate_logger()
    {
        if (log.isSet())
        {
            global_logger.reset(Logger::create_file_logger(log.getValue()));
        }
        else if (background.getValue())
        {
            global_logger->warn("securefs is about to enter background without a log file. You "
                                "won't be able to inspect what goes wrong. You can remount with "
                                "option --log instead.");
            global_logger.reset(Logger::create_null_logger());
        }
        if (trace.getValue())
            global_logger->set_level(kLogTrace);
    }

    int execute() override
    {
        recreate_logger();
        OSService::get_default().ensure_directory(mount_point.getValue(), 0755);
        std::shared_ptr<FileStream> config_stream;
        try
        {
            config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        }
        catch (const ExceptionBase& e)
        {
            if (e.error_number() == ENOENT)
            {
                global_logger->error(
                    "Config file %s does not exist. Perhaps you forget to run `create` command "
                    "first?",
                    get_real_config_path().c_str());
                return 19;
            }
            throw;
        }
        auto config = read_config(config_stream.get(), password.data(), password.size());
        config_stream.reset();

        if (config.master_key.size() == KEY_LENGTH
            && std::count(config.master_key.begin(), config.master_key.end(), (byte)0) >= 20)
        {
            global_logger->warn(
                "%s",
                "Your filesystem is created by a vulnerable version of securefs.\n"
                "Please immediate migrate your old data to a newly created securefs filesystem,\n"
                "and remove all traces of old data to avoid information leakage!");
            fputs("Do you wish to continue with mounting? (y/n)", stdout);
            fflush(stdout);
            if (getc(stdout) != 'y')
                return 0;
        }
        generate_random(password.data(), password.size());    // Erase user input

        try
        {
            global_logger->info("Raising the number of file descriptor limit to %d",
                                OSService::raise_fd_limit());
        }
        catch (const ExceptionBase& e)
        {
            global_logger->warn("Failure to raise the maximum file descriptor limit (%s: %s)",
                                e.type_name(),
                                e.what());
        }

        std::vector<const char*> fuse_args;
        fuse_args.push_back("securefs");
        fuse_args.push_back("-s");
        if (!background.getValue())
            fuse_args.push_back("-f");
        if (fuse_options.isSet())
        {
            for (const std::string& opt : fuse_options.getValue())
            {
                fuse_args.push_back("-o");
                fuse_args.push_back(opt.c_str());
            }
        }
#ifdef __APPLE__
        const char* copyfile_disable = ::getenv("COPYFILE_DISABLE");
        if (copyfile_disable)
        {
            global_logger->info(
                "Mounting without .DS_Store and other apple dot files because environmental "
                "variable COPYFILE_DISABLE is set to \"%s\"",
                copyfile_disable);
            fuse_args.push_back("-o");
            fuse_args.push_back("noappledouble");
        }
#endif
        fuse_args.push_back(mount_point.getValue().c_str());

        global_logger->info("Mounting filesystem stored at %s onto %s with format version: %u",
                            data_dir.getValue().c_str(),
                            mount_point.getValue().c_str(),
                            config.version);

        if (config.version < 4)
        {
            operations::MountOptions fsopt;
            fsopt.root = std::make_shared<OSService>(data_dir.getValue());
            try
            {
                fsopt.lock_stream = fsopt.root->open_file_stream(
                    securefs::operations::LOCK_FILENAME, O_CREAT | O_EXCL | O_RDONLY, 0644);
            }
            catch (const ExceptionBase& e)
            {
                global_logger->error(
                    "Encountering error %s when creating the lock file %s/%s.\n"
                    "Perhaps multiple securefs instances are trying to operate on a single "
                    "directory.\n"
                    "Close other instances, including on other machines, and try again.\n"
                    "Or remove the lock file manually if you are sure no other instances are "
                    "holding the lock.",
                    e.what(),
                    data_dir.getValue().c_str(),
                    securefs::operations::LOCK_FILENAME.c_str());
                return 18;
            }
            fsopt.block_size = config.block_size;
            fsopt.iv_size = config.iv_size;
            fsopt.version = config.version;

            copy_key(config.master_key, &fsopt.master_key);
            fsopt.flags = config.version < 3 ? 0 : FileTable::STORE_TIME;
            if (insecure.getValue())
                fsopt.flags.value() |= FileTable::NO_AUTHENTICATION;
            if (uid_override.isSet())
            {
                fsopt.uid_override = uid_override.getValue();
            }
            if (gid_override.isSet())
            {
                fsopt.gid_override = gid_override.getValue();
            }
            struct fuse_operations operations;

            init_fuse_operations(data_dir.getValue().c_str(), operations, !noxattr.getValue());

            return fuse_main(static_cast<int>(fuse_args.size()),
                             const_cast<char**>(fuse_args.data()),
                             &operations,
                             &fsopt);
        }
        else
        {
            lite::MountOptions fsopt;
            fsopt.root = std::make_shared<OSService>(data_dir.getValue());
            fsopt.block_size = config.block_size;
            fsopt.iv_size = config.iv_size;

            if (config.master_key.size() != 3 * KEY_LENGTH)
            {
                global_logger->error(
                    "The config file has an invalid master key size %zu (expect %zu)",
                    config.master_key.size(),
                    static_cast<size_t>(3 * KEY_LENGTH));
                return 100;
            }

            memcpy(fsopt.name_key.data(), config.master_key.data(), KEY_LENGTH);
            memcpy(fsopt.content_key.data(), config.master_key.data() + KEY_LENGTH, KEY_LENGTH);
            memcpy(fsopt.xattr_key.data(), config.master_key.data() + 2 * KEY_LENGTH, KEY_LENGTH);

            struct fuse_operations operations;
            lite::init_fuse_operations(&operations, data_dir.getValue(), mount_point.getValue());
            return fuse_main(static_cast<int>(fuse_args.size()),
                             const_cast<char**>(fuse_args.data()),
                             &operations,
                             &fsopt);
        }
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
        "s", "stdinpass", "Compatibility flag with older version. Does nothing."};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&stdinpass);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.parse(argc, argv);

        password.resize(MAX_PASS_LEN);
        if (!OSService::isatty(0))
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
        auto config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        auto config = read_config(config_stream.get(), password.data(), password.size());
        config_stream.reset();

        if (config.version >= 4)
        {
            fprintf(stderr,
                    "The filesystem has format version %u which cannot be fixed\n",
                    config.version);
            return 3;
        }
        generate_random(password.data(), password.size());    // Erase user input

        operations::MountOptions fsopt;
        fsopt.root = std::make_shared<OSService>(data_dir.getValue());
        fsopt.root->lock();
        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        copy_key(config.master_key, &fsopt.master_key);
        fsopt.flags = 0;

        operations::FileSystemContext fs(fsopt);
        fix(data_dir.getValue(), &fs);
        return 0;
    }

    const char* long_name() const noexcept override { return "fix"; }

    char short_name() const noexcept override { return 0; }

    const char* help_message() const noexcept override
    {
        return "Try to fix errors in an existing filesystem";
    }
};

class VersionCommand : public CommandBase
{
private:
    const char* version_string = "0.7.0";

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        (void)argc;
        (void)argv;
    }

    int execute() override
    {
        using namespace CryptoPP;
        fprintf(
            stdout, "securefs %s (with Crypto++ %g)\n\n", version_string, CRYPTOPP_VERSION / 100.0);
#ifdef CRYPTOPP_DISABLE_ASM
        fputs("Built without hardware acceleration\n", stdout);
#else
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        fprintf(stdout,
                "Hardware features available:\nSSE2: %s\nSSE3: %s\nAES-NI: "
                "%s\nCLMUL: %s\n",
                HasSSE2() ? "true" : "false",
                HasSSSE3() ? "true" : "false",
                HasAESNI() ? "true" : "false",
                HasCLMUL() ? "true" : "false");
#endif
#endif
        return 0;
    }

    const char* long_name() const noexcept override { return "version"; }

    char short_name() const noexcept override { return 'v'; }

    const char* help_message() const noexcept override { return "Show version of the program"; }
};

std::string process_name;

int commands_main(int argc, const char* const* argv)
{
    try
    {
        std::vector<std::unique_ptr<CommandBase>> cmds;
        cmds.reserve(6);
        cmds.push_back(make_unique<MountCommand>());
        cmds.push_back(make_unique<CreateCommand>());
        cmds.push_back(make_unique<ChangePasswordCommand>());
        cmds.push_back(make_unique<FixCommand>());
        cmds.push_back(make_unique<VersionCommand>());

        auto print_usage = [&]() {
            fputs("Available subcommands:\n\n", stderr);

            for (auto&& command : cmds)
            {
                if (command->short_name())
                {
                    fprintf(stderr,
                            "%s (alias: %c): %s\n",
                            command->long_name(),
                            command->short_name(),
                            command->help_message());
                }
                else
                {
                    fprintf(stderr, "%s: %s\n", command->long_name(), command->help_message());
                }
            }

            fprintf(stderr, "\nType %s ${SUBCOMMAND} --help for details\n", argv[0]);
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
        global_logger->error(
            "Error parsing arguments: %s at %s\n", e.error().c_str(), e.argId().c_str());
        return 5;
    }
    catch (const std::runtime_error& e)
    {
        global_logger->error("%s\n", e.what());
        return 1;
    }
    catch (const securefs::ExceptionBase& e)
    {
        global_logger->error("%s: %s\n", e.type_name(), e.what());
        return 2;
    }
    catch (const std::exception& e)
    {
        global_logger->error("%s: %s\n", typeid(e).name(), e.what());
        return 3;
    }
}
}
