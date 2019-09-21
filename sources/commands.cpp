#include "commands.h"
#include "exceptions.h"
#include "git-version.h"
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
#include <unordered_map>
#include <vector>

#include <fuse.h>

#ifdef _MSC_VER
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

using namespace securefs;

namespace
{

static const char* CONFIG_FILE_NAME = ".securefs.json";
static const unsigned MIN_ITERATIONS = 20000;
static const unsigned MIN_DERIVE_SECONDS = 1;
static const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;
static const char* PBKDF_ALGO_PKCS5 = "pkcs5-pbkdf2-hmac-sha256";
static const char* PBKDF_ALGO_SCRYPT = "scrypt";

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
                            const std::string& pbkdf_algorithm,
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

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        config["iterations"] = securefs::pbkdf_hmac_sha256(password,
                                                           pass_len,
                                                           salt.data(),
                                                           salt.size(),
                                                           rounds ? rounds : MIN_ITERATIONS,
                                                           rounds ? 0 : MIN_DERIVE_SECONDS,
                                                           key_to_encrypt.data(),
                                                           key_to_encrypt.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        uint32_t N = rounds > 0 ? rounds : 65536, r = 8, p = 1;
        config["iterations"] = N;
        config["scrypt_r"] = r;
        config["scrypt_p"] = p;
        securefs::libscrypt_scrypt(static_cast<const byte*>(password),
                                   pass_len,
                                   salt.data(),
                                   salt.size(),
                                   N,
                                   r,
                                   p,
                                   key_to_encrypt.data(),
                                   key_to_encrypt.size());
    }
    else
    {
        throw_runtime_error("Unknown pbkdf algorithm " + pbkdf_algorithm);
    }
    config["pbkdf"] = pbkdf_algorithm;

    config["salt"] = securefs::hexify(salt);

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    generate_random(iv, array_length(iv));

    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key_to_encrypt.data(), key_to_encrypt.size(), iv, array_length(iv));
    encryptor.EncryptAndAuthenticate(encrypted_master_key.data(),
                                     mac,
                                     array_length(mac),
                                     iv,
                                     array_length(iv),
                                     reinterpret_cast<const byte*>(get_version_header(version)),
                                     strlen(get_version_header(version)),
                                     master_key.data(),
                                     master_key.size());

    Json::Value encrypted_key;
    encrypted_key["IV"] = securefs::hexify(iv, array_length(iv));
    encrypted_key["MAC"] = securefs::hexify(mac, array_length(mac));
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
    const auto& encrypted_key_json_value = config["encrypted_key"];
    std::string iv_hex = encrypted_key_json_value["IV"].asString();
    std::string mac_hex = encrypted_key_json_value["MAC"].asString();
    std::string ekey_hex = encrypted_key_json_value["key"].asString();

    parse_hex(salt_hex, salt.data(), salt.size());
    parse_hex(iv_hex, iv, array_length(iv));
    parse_hex(mac_hex, mac, array_length(mac));

    encrypted_key.resize(ekey_hex.size() / 2);
    parse_hex(ekey_hex, encrypted_key.data(), encrypted_key.size());
    master_key.resize(encrypted_key.size());

    std::string pbkdf_algorithm = config.get("pbkdf", PBKDF_ALGO_PKCS5).asString();
    VERBOSE_LOG("Setting the password key derivation function to %s", pbkdf_algorithm.c_str());

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        pbkdf_hmac_sha256(password,
                          pass_len,
                          salt.data(),
                          salt.size(),
                          iterations,
                          0,
                          key_to_encrypt_master_key.data(),
                          key_to_encrypt_master_key.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        auto r = config["scrypt_r"].asUInt();
        auto p = config["scrypt_p"].asUInt();
        libscrypt_scrypt(static_cast<const byte*>(password),
                         pass_len,
                         salt.data(),
                         salt.size(),
                         iterations,
                         r,
                         p,
                         key_to_encrypt_master_key.data(),
                         key_to_encrypt_master_key.size());
    }
    else
    {
        throw_runtime_error("Unknown pbkdf algorithm " + pbkdf_algorithm);
    }

    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(
        key_to_encrypt_master_key.data(), key_to_encrypt_master_key.size(), iv, array_length(iv));
    return decryptor.DecryptAndVerify(master_key.data(),
                                      mac,
                                      array_length(mac),
                                      iv,
                                      array_length(iv),
                                      reinterpret_cast<const byte*>(get_version_header(version)),
                                      strlen(get_version_header(version)),
                                      encrypted_key.data(),
                                      encrypted_key.size());
}
}    // namespace

namespace securefs
{

std::shared_ptr<FileStream> CommandBase::open_config_stream(const std::string& path, int flags)
{
    return OSService::get_default().open_file_stream(path, flags, 0644);
}

FSConfig CommandBase::read_config(FileStream* stream, const void* password, size_t pass_len)
{
    FSConfig result;

    std::vector<char> str;
    str.reserve(4000);
    while (true)
    {
        char buffer[4000];
        auto sz = stream->sequential_read(buffer, sizeof(buffer));
        if (sz <= 0)
            break;
        str.insert(str.end(), buffer, buffer + sz);
    }

    Json::Reader reader;
    Json::Value value;
    if (!reader.parse(str.data(), str.data() + str.size(), value))
        throw_runtime_error(strprintf("Failure to parse the config file: %s",
                                      reader.getFormattedErrorMessages().c_str()));

    if (!parse_config(
            value, password, pass_len, result.master_key, result.block_size, result.iv_size))
        throw_runtime_error("Invalid password");
    result.version = value["version"].asUInt();
    return result;
}

static void copy_key(const CryptoPP::AlignedSecByteBlock& in_key, key_type* out_key)
{
    if (in_key.size() != out_key->size())
        throw_runtime_error("Invalid key size");
    memcpy(out_key->data(), in_key.data(), out_key->size());
}

static void copy_key(const CryptoPP::AlignedSecByteBlock& in_key, optional<key_type>* out_key)
{
    out_key->emplace();
    copy_key(in_key, &(out_key->value()));
}

void CommandBase::write_config(FileStream* stream,
                               const std::string& pbdkf_algorithm,
                               const FSConfig& config,
                               const void* password,
                               size_t pass_len,
                               unsigned rounds)
{
    key_type salt;
    generate_random(salt.data(), salt.size());
    auto str = generate_config(config.version,
                               pbdkf_algorithm,
                               config.master_key,
                               salt,
                               password,
                               pass_len,
                               config.block_size,
                               config.iv_size,
                               rounds)
                   .toStyledString();
    stream->sequential_write(str.data(), str.size());
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
                                   : data_dir.getValue() + PATH_SEPARATOR_CHAR + CONFIG_FILE_NAME;
    }
};

static const std::string message_for_setting_pbkdf
    = strprintf("The algorithm to stretch passwords. Use %s for maximum protection (default), or "
                "%s for compatibility with old versions of securefs",
                PBKDF_ALGO_SCRYPT,
                PBKDF_ALGO_PKCS5);

class CreateCommand : public CommonCommandBase
{
private:
    CryptoPP::AlignedSecByteBlock password;

    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of key derivation are applied (0 for automatic)",
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
    TCLAP::ValueArg<std::string> pbkdf{
        "", "pbkdf", message_for_setting_pbkdf, false, PBKDF_ALGO_SCRYPT, "string"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&iv_size);
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

        OSService::read_password_with_confirmation("Password: ", &password);
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
        CryptoPP::OS_GenerateRandomBlock(false, config.master_key.data(), config.master_key.size());

        config.iv_size = format_version == 1 ? 32 : iv_size.getValue();
        config.version = format_version;
        config.block_size = block_size.getValue();

        auto config_stream
            = open_config_stream(get_real_config_path(), O_WRONLY | O_CREAT | O_EXCL);
        DEFER(if (std::uncaught_exception()) {
            OSService::get_default().remove_file(get_real_config_path());
        });
        write_config(config_stream.get(),
                     pbkdf.getValue(),
                     config,
                     password.data(),
                     password.size(),
                     rounds.getValue());
        config_stream.reset();

        if (format_version < 4)
        {
            operations::MountOptions opt;
            opt.version = format_version;
            opt.root = std::make_shared<OSService>(data_dir.getValue());
            opt.master_key = config.master_key;
            opt.flags = format_version < 3 ? 0 : kOptionStoreTime;
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
        "Specify how many rounds of key derivation are applied (0 for automatic)",
        false,
        0,
        "integer"};
    TCLAP::ValueArg<std::string> pbkdf{
        "", "pbkdf", message_for_setting_pbkdf, false, PBKDF_ALGO_SCRYPT, "string"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&rounds);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.parse(argc, argv);
        OSService::read_password_no_confirmation("Old password: ", &old_password);
        OSService::read_password_with_confirmation("New password: ", &new_password);
    }

    int execute() override
    {
        auto original_path = get_real_config_path();
        byte buffer[16];
        generate_random(buffer, array_length(buffer));
        auto tmp_path = original_path + hexify(buffer, array_length(buffer));
        auto stream = OSService::get_default().open_file_stream(original_path, O_RDONLY, 0644);
        auto config = read_config(stream.get(), old_password.data(), old_password.size());
        stream = OSService::get_default().open_file_stream(
            tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        DEFER(if (std::uncaught_exception()) { OSService::get_default().remove_file(tmp_path); });
        write_config(stream.get(),
                     pbkdf.getValue(),
                     config,
                     new_password.data(),
                     new_password.size(),
                     rounds.getValue());
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
    CryptoPP::AlignedSecByteBlock password;
    TCLAP::SwitchArg single_threaded{"s", "single", "Single threaded mode"};
    TCLAP::SwitchArg background{
        "b", "background", "Run securefs in the background (currently no effect on Windows)"};
    TCLAP::SwitchArg insecure{
        "i", "insecure", "Disable all integrity verification (insecure mode)"};
    TCLAP::SwitchArg noxattr{"x", "noxattr", "Disable built-in xattr support"};
    TCLAP::SwitchArg verbose{"v", "verbose", "Logs more verbose messages"};
    TCLAP::SwitchArg trace{"", "trace", "Trace all calls into `securefs` (implies --verbose)"};
    TCLAP::ValueArg<std::string> log{
        "", "log", "Path of the log file (may contain sensitive information)", false, "", "path"};
    TCLAP::MultiArg<std::string> fuse_options{
        "o",
        "opt",
        "Additional FUSE options; this may crash the filesystem; use only for testing!",
        false,
        "options"};
    TCLAP::UnlabeledValueArg<std::string> mount_point{
        "mount_point", "Mount point", true, "", "mount_point"};
    TCLAP::SwitchArg case_insensitive{"",
                                      "insensitive",
                                      "Converts the case of all filenames so "
                                      "that it works case insensitively"};
    TCLAP::SwitchArg enable_nfc{"",
                                "nfc",
                                "Normalizes all filenames to normal form composed (NFC). Many "
                                "macOS applications may not work properly if this is not enabled."};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());

#ifdef __APPLE__
        cmdline.add(&noxattr);
#endif

        cmdline.add(&background);
        // cmdline.add(&insecure);
        cmdline.add(&verbose);
        cmdline.add(&trace);
        cmdline.add(&log);
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.add(&mount_point);
        cmdline.add(&pass);
        cmdline.add(&fuse_options);
        cmdline.add(&single_threaded);
        cmdline.add(&case_insensitive);
        cmdline.parse(argc, argv);

        if (pass.isSet() && !pass.getValue().empty())
        {
            password.resize(pass.getValue().size());
            memcpy(password.data(), pass.getValue().data(), password.size());
            generate_random(reinterpret_cast<byte*>(&pass.getValue()[0]), pass.getValue().size());
        }
        else
        {
            OSService::read_password_no_confirmation("Password: ", &password);
        }

        if (global_logger && verbose.getValue())
            global_logger->set_level(kLogVerbose);
        if (global_logger && trace.getValue())
            global_logger->set_level(kLogTrace);
    }

    void recreate_logger()
    {
        if (log.isSet())
        {
            auto logger = Logger::create_file_logger(log.getValue());
            delete global_logger;
            global_logger = logger;
        }
        else if (background.getValue())
        {
            WARN_LOG("securefs is about to enter background without a log file. You "
                     "won't be able to inspect what goes wrong. You can remount with "
                     "option --log instead.");
            delete global_logger;
            global_logger = nullptr;
        }
        if (global_logger && verbose.getValue())
            global_logger->set_level(kLogVerbose);
        if (global_logger && trace.getValue())
            global_logger->set_level(kLogTrace);
    }

    int execute() override
    {
        if (data_dir.getValue() == mount_point.getValue())
        {
            WARN_LOG("Mounting a directory on itself may cause securefs to hang");
        }

#ifdef WIN32
        auto is_letter = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); };
        if (mount_point.getValue().size() != 2 || mount_point.getValue()[1] != ':'
            || !is_letter(mount_point.getValue().front()))
        {
            ERROR_LOG("The mount point must be a drive path, such as Z:");
            return 33;
        }
#else
        try
        {
            OSService::get_default().mkdir(mount_point.getValue(), 0755);
        }
        catch (const std::exception& e)
        {
            VERBOSE_LOG("%s (ignore this error if mounting succeeds eventually)", e.what());
        }
#endif
        std::shared_ptr<FileStream> config_stream;
        try
        {
            config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        }
        catch (const ExceptionBase& e)
        {
            if (e.error_number() == ENOENT)
            {
                ERROR_LOG("Encounter exception %s", e.what());
                ERROR_LOG(
                    "Config file %s does not exist. Perhaps you forget to run `create` command "
                    "first?",
                    get_real_config_path().c_str());
                return 19;
            }
            throw;
        }
        auto config = read_config(config_stream.get(), password.data(), password.size());
        config_stream.reset();
        CryptoPP::SecureWipeBuffer(password.data(), password.size());

        bool is_vulnerable = popcount(config.master_key.data(), config.master_key.size())
            <= config.master_key.size();
        if (is_vulnerable)
        {
            WARN_LOG(
                "%s",
                "Your filesystem is created by a vulnerable version of securefs.\n"
                "Please immediate migrate your old data to a newly created securefs filesystem,\n"
                "and remove all traces of old data to avoid information leakage!");
            fputs("Do you wish to continue with mounting? (y/n)", stdout);
            fflush(stdout);
            if (getchar() != 'y')
                return 110;
        }

        try
        {
            int fd_limit = OSService::raise_fd_limit();
            VERBOSE_LOG("Raising the number of file descriptor limit to %d", fd_limit);
        }
        catch (const std::exception& e)
        {
            WARN_LOG("Failure to raise the maximum file descriptor limit (%s: %s)",
                     get_type_name(e).get(),
                     e.what());
        }

        std::vector<const char*> fuse_args;
        fuse_args.push_back("securefs");
        if (config.version < 4 || single_threaded.getValue())
        {
            fuse_args.push_back("-s");
        }
        if (!background.getValue())
            fuse_args.push_back("-f");

#ifdef __APPLE__
        const char* copyfile_disable = ::getenv("COPYFILE_DISABLE");
        if (copyfile_disable)
        {
            VERBOSE_LOG("Mounting without .DS_Store and other apple dot files because "
                        "environmental "
                        "variable COPYFILE_DISABLE is set to \"%s\"",
                        copyfile_disable);
            fuse_args.push_back("-o");
            fuse_args.push_back("noappledouble");
        }
#elif _WIN32
        fuse_args.push_back("-ouid=-1,gid=-1");
#endif

        if (fuse_options.isSet())
        {
            for (const std::string& opt : fuse_options.getValue())
            {
                fuse_args.push_back("-o");
                fuse_args.push_back(opt.c_str());
            }
        }

        fuse_args.push_back(mount_point.getValue().c_str());

        VERBOSE_LOG("Filesystem parameters: format version %d, block size %u (bytes), iv size %u "
                    "(bytes)",
                    config.version,
                    config.block_size,
                    config.iv_size);

        if (!is_vulnerable)
        {
            VERBOSE_LOG("Master key: %s", hexify(config.master_key).c_str());
        }

        operations::MountOptions fsopt;
        fsopt.root = std::make_shared<OSService>(data_dir.getValue());
        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        fsopt.master_key = config.master_key;
        fsopt.flags = config.version < 3 ? 0 : kOptionStoreTime;
        if (insecure.getValue())
            fsopt.flags.value() |= kOptionNoAuthentication;
        if (case_insensitive.getValue())
        {
            INFO_LOG("Mounting as a case insensitive filesystem");
            fsopt.flags.value() |= kOptionCaseFoldFileName;
        }
        if (enable_nfc.getValue())
        {
            INFO_LOG("Mounting as a Unicode normalized filesystem");
            fsopt.flags.value() |= kOptionNFCFileName;
        }
        std::shared_ptr<FileStream> lock_stream;
        DEFER(if (lock_stream) {
            lock_stream->close();
            lock_stream.reset();
            fsopt.root->remove_file_nothrow(operations::LOCK_FILENAME);
        });

        if (config.version < 4)
        {

            try
            {
                lock_stream = fsopt.root->open_file_stream(
                    securefs::operations::LOCK_FILENAME, O_CREAT | O_EXCL | O_RDONLY, 0644);
            }
            catch (const ExceptionBase& e)
            {
                ERROR_LOG("Encountering error %s when creating the lock file %s/%s.\n"
                          "Perhaps multiple securefs instances are trying to operate on a single "
                          "directory.\n"
                          "Close other instances, including on other machines, and try again.\n"
                          "Or remove the lock file manually if you are sure no other instances are "
                          "holding the lock.",
                          e.what(),
                          data_dir.getValue().c_str(),
                          securefs::operations::LOCK_FILENAME);
                return 18;
            }
        }

        bool native_xattr = !noxattr.getValue();
#ifdef __APPLE__
        if (native_xattr)
        {
            auto rc = fsopt.root->listxattr(".", nullptr, 0);
            if (rc < 0)
            {
                fprintf(stderr,
                        "Warning: %s has no extended attribute support.\nXattr is disabled\n",
                        data_dir.getValue().c_str());
                native_xattr = false;
            }
        }
#endif

        struct fuse_operations operations;
        if (config.version <= 3)
        {
            operations::init_fuse_operations(&operations, native_xattr);
        }
        else
        {
            lite::init_fuse_operations(&operations, native_xattr);
        }
        recreate_logger();
        return fuse_main(static_cast<int>(fuse_args.size()),
                         const_cast<char**>(fuse_args.data()),
                         &operations,
                         &fsopt);
    }

    const char* long_name() const noexcept override { return "mount"; }

    char short_name() const noexcept override { return 'm'; }

    const char* help_message() const noexcept override { return "Mount an existing filesystem"; }
};

class FixCommand : public CommonCommandBase
{
private:
    CryptoPP::AlignedSecByteBlock password;

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&data_dir);
        cmdline.add(&config_path);
        cmdline.parse(argc, argv);

        OSService::read_password_no_confirmation("Password: ", &password);
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
        fsopt.master_key = config.master_key;
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

static inline const char* true_or_false(bool v) { return v ? "true" : "false"; }

class VersionCommand : public CommandBase
{
public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        (void)argc;
        (void)argv;
    }

    int execute() override
    {
        using namespace CryptoPP;
        printf("securefs %s\n", GIT_VERSION);
        printf("Crypto++ %g\n", CRYPTOPP_VERSION / 100.0);
#ifdef WIN32
        HMODULE hd = GetModuleHandleW((sizeof(void*) == 8) ? L"winfsp-x64.dll" : L"winfsp-x86.dll");
        NTSTATUS(*fsp_version_func)
        (uint32_t*)
            = reinterpret_cast<decltype(fsp_version_func)>(GetProcAddress(hd, "FspVersion"));
        if (fsp_version_func)
        {
            uint32_t vn;
            if (fsp_version_func(&vn) == 0)
            {
                printf("WinFsp %u.%u\n", vn >> 16, vn & 0xFFFFu);
            }
        }
#elif defined(__APPLE__)
        typedef const char* version_function(void);
        auto osx_version_func
            = reinterpret_cast<version_function*>(::dlsym(RTLD_DEFAULT, "osxfuse_version"));
        if (osx_version_func)
            printf("osxfuse %s\n", osx_version_func());
#else
        typedef int version_function(void);
        auto fuse_version_func
            = reinterpret_cast<version_function*>(::dlsym(RTLD_DEFAULT, "fuse_version"));
        printf("libfuse %d\n", fuse_version_func());
#endif

#ifdef CRYPTOPP_DISABLE_ASM
        fputs("\nBuilt without hardware acceleration\n", stdout);
#else
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        fprintf(stdout,
                "\nHardware features available:\nSSE2: %s\nSSE3: %s\nSSE4.1: %s\nSSE4.2: "
                "%s\nAES-NI: %s\nCLMUL: %s\nSHA: %s\n",
                HasSSE2() ? "true" : "false",
                HasSSSE3() ? "true" : "false",
                HasSSE41() ? "true" : "false",
                HasSSE42() ? "true" : "false",
                HasAESNI() ? "true" : "false",
                HasCLMUL() ? "true" : "false",
                HasSHA() ? "true" : "false");
#endif
#endif
        return 0;
    }

    const char* long_name() const noexcept override { return "version"; }

    char short_name() const noexcept override { return 'v'; }

    const char* help_message() const noexcept override { return "Show version of the program"; }
};

class InfoCommand : public CommandBase
{
private:
    TCLAP::UnlabeledValueArg<std::string> path{
        "path", "Directory or the filename of the config file", true, "", "path"};

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        TCLAP::CmdLine cmdline(help_message());
        cmdline.add(&path);
        cmdline.parse(argc, argv);
    }

    const char* long_name() const noexcept override { return "info"; }

    char short_name() const noexcept override { return 'i'; }

    const char* help_message() const noexcept override
    {
        return "Display information about the filesystem";
    }

    int execute() override
    {
        std::shared_ptr<FileStream> fs;
        struct fuse_stat st;
        if (!OSService::get_default().stat(path.getValue(), &st))
        {
            ERROR_LOG("The path %s does not exist.", path.getValue().c_str());
        }

        std::string real_config_path = path.getValue();
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            real_config_path.append("/.securefs.json");
        fs = OSService::get_default().open_file_stream(real_config_path, O_RDONLY, 0);

        Json::Value config_json;

        {
            Json::Reader reader;
            std::string buffer(fs->size(), 0);
            fs->read(&buffer[0], 0, buffer.size());
            reader.parse(buffer, config_json);
        }

        unsigned format_version = config_json["version"].asUInt();
        if (format_version < 1 || format_version > 4)
        {
            ERROR_LOG("Unknown filesystem format version %u", format_version);
            return 44;
        }
        printf("Config file path: %s\n", real_config_path.c_str());
        printf("Filesystem format version: %u\n", format_version);
        printf("Is full or lite format: %s\n", (format_version < 4) ? "full" : "lite");
        printf("Is underlying directory flattened: %s\n", true_or_false(format_version < 4));
        printf("Is multiple mounts allowed: %s\n", true_or_false(format_version >= 4));
        printf("Is timestamp stored within the fs: %s\n\n", true_or_false(format_version == 3));

        printf("Content block size: %u bytes\n",
               format_version == 1 ? 4096 : config_json["block_size"].asUInt());
        printf("Content IV size: %u bits\n",
               format_version == 1 ? 256 : config_json["iv_size"].asUInt() * 8);
        printf("Password derivation algorithm: PBKDF2-HMAC-SHA256\n");
        printf("Password derivation iterations: %u\n", config_json["iterations"].asUInt());
        printf("Per file key generation algorithm: %s\n",
               format_version < 4 ? "HMAC-SHA256" : "AES");
        printf("Content cipher: %s\n", format_version < 4 ? "AES-256-GCM" : "AES-128-GCM");
        return 0;
    }
};

int commands_main(int argc, const char* const* argv)
{
    try
    {
        std::unique_ptr<CommandBase> cmds[] = {make_unique<MountCommand>(),
                                               make_unique<CreateCommand>(),
                                               make_unique<ChangePasswordCommand>(),
                                               make_unique<FixCommand>(),
                                               make_unique<VersionCommand>(),
                                               make_unique<InfoCommand>()};

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
        ERROR_LOG("Error parsing arguments: %s at %s\n", e.error().c_str(), e.argId().c_str());
        return 5;
    }
    catch (const std::runtime_error& e)
    {
        ERROR_LOG("%s\n", e.what());
        return 1;
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("%s: %s\n", get_type_name(e).get(), e.what());
        return 2;
    }
}
}    // namespace securefs
