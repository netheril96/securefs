#include "commands.h"
#include "exceptions.h"
#include "git-version.h"
#include "lite_operations.h"
#include "lock_enabled.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"
#include "win_get_proc.h"

#include <absl/types/optional.h>
#include <argon2.h>
#include <cryptopp/cpu.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/secblock.h>
#include <fuse.h>
#include <json/json.h>
#include <tclap/CmdLine.h>
#include <utf8proc.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

using namespace securefs;

namespace
{

const char* const CONFIG_FILE_NAME = ".securefs.json";
const unsigned MIN_ITERATIONS = 20000;
const unsigned MIN_DERIVE_SECONDS = 1;
const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;

const char* const PBKDF_ALGO_PKCS5 = "pkcs5-pbkdf2-hmac-sha256";
const char* const PBKDF_ALGO_SCRYPT = "scrypt";
const char* const PBKDF_ALGO_ARGON2ID = "argon2id";

const char* const EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED = " ";

const char* get_version_header(unsigned version)
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

std::unique_ptr<Json::CharReader> create_json_reader()
{
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    return std::unique_ptr<Json::CharReader>(builder.newCharReader());
}

enum class NLinkFixPhase
{
    CollectingNLink,
    FixingNLink
};

void fix_hardlink_count(operations::FileSystemContext* fs,
                        Directory* dir,
                        absl::flat_hash_map<id_type, int, id_hash>* nlink_map,
                        NLinkFixPhase phase)
{
    std::vector<std::pair<id_type, int>> listings;
    {
        FileLockGuard file_lock_guard(*dir);
        dir->iterate_over_entries(
            [&listings](const std::string&, const id_type& id, int type)
            {
                listings.emplace_back(id, type);
                return true;
            });
    }

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
        {
            auto& fp = *base;
            FileLockGuard file_lock_guard(fp);
            fp.set_nlink(nlink_map->at(id));
        }
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
    {
        FileLockGuard file_lock_guard(*dir);
        dir->iterate_over_entries(
            [&listings](const std::string& name, const id_type& id, int type)
            {
                listings.emplace_back(name, id, type);
                return true;
            });
    }

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
            absl::FPrintF(
                stderr,
                "Encounter exception when opening %s: %s\nDo you want to remove the entry? "
                "(Yes/No, default: no)\n",
                (dir_name + '/' + name),
                e.what());
            auto remove = [&]()
            {
                FileLockGuard file_lock_guard(*dir);
                dir->remove_entry(name, id, type);
            };
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
            absl::PrintF(
                "Mismatch type for %s (inode has type %s, directory entry has type %s). Do you "
                "want to fix it? (Yes/No default: yes)\n",
                (dir_name + '/' + name),
                FileBase::type_name(real_type),
                FileBase::type_name(type));
            fflush(stdout);

            auto fix_type = [&]()
            {
                FileLockGuard file_lock_guard(*dir);
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
            absl::PrintF(
                "%s is not referenced anywhere in the filesystem, do you want to recover it? "
                "([r]ecover/[d]elete/[i]gnore default: recover)\n",
                hexify(id));
            fflush(stdout);

            auto recover = [&]()
            {
                auto base = open_as(fs->table, id, FileBase::BASE);
                auto& root_dir_fp = *root_dir;
                FileLockGuard file_lock_guard(root_dir_fp);
                root_dir_fp.cast_as<Directory>()->add_entry(hexify(id), id, base->get_real_type());
            };

            auto remove = [&]()
            {
                FileBase* base = fs->table.open_as(id, FileBase::BASE);
                int real_type = base->get_real_type();
                fs->table.close(base);
                auto real_file_handle = open_as(fs->table, id, real_type);
                auto& fp = *real_file_handle;
                FileLockGuard file_lock_guard(fp);
                fp.unlink();
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

    absl::flat_hash_map<id_type, int, id_hash> nlink_map;
    puts("Fixing hardlink count ...");
    fix_hardlink_count(
        fs, root_dir.get_as<Directory>(), &nlink_map, NLinkFixPhase::CollectingNLink);
    fix_hardlink_count(fs, root_dir.get_as<Directory>(), &nlink_map, NLinkFixPhase::FixingNLink);
    puts("Fix complete");
}

void hmac_sha256(const securefs::key_type& base_key,
                 StringRef maybe_key_file_path,
                 securefs::key_type& out_key)
{
    if (maybe_key_file_path.empty())
    {
        out_key = base_key;
        return;
    }
    auto file_stream = OSService::get_default().open_file_stream(maybe_key_file_path, O_RDONLY, 0);
    byte buffer[4096];
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(base_key.data(), base_key.size());
    while (true)
    {
        auto sz = file_stream->sequential_read(buffer, sizeof(buffer));
        if (sz <= 0)
        {
            break;
        }
        hmac.Update(buffer, sz);
    }
    hmac.TruncatedFinal(out_key.data(), out_key.size());
}

Json::Value generate_config(const std::string& pbkdf_algorithm,
                            StringRef maybe_key_file_path,
                            const securefs::key_type& salt,
                            const void* password,
                            size_t pass_len,
                            unsigned rounds,
                            const FSConfig& fsconfig)
{
    securefs::key_type effective_salt;
    hmac_sha256(salt, maybe_key_file_path, effective_salt);

    Json::Value config;
    config["version"] = fsconfig.version;
    key_type password_derived_key;
    CryptoPP::AlignedSecByteBlock encrypted_master_key(nullptr, fsconfig.master_key.size());

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        config["iterations"] = pbkdf_hmac_sha256(password,
                                                 pass_len,
                                                 effective_salt.data(),
                                                 effective_salt.size(),
                                                 rounds ? rounds : MIN_ITERATIONS,
                                                 rounds ? 0 : MIN_DERIVE_SECONDS,
                                                 password_derived_key.data(),
                                                 password_derived_key.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        uint32_t n = rounds > 0 ? rounds : (1u << 18u), r = 8, p = 1;
        config["iterations"] = n;
        config["scrypt_r"] = r;
        config["scrypt_p"] = p;
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(password_derived_key.data(),
                         password_derived_key.size(),
                         static_cast<const byte*>(password),
                         pass_len,
                         effective_salt.data(),
                         effective_salt.size(),
                         n,
                         r,
                         p);
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_ARGON2ID)
    {
        const char* env_m_cost = getenv("SECUREFS_ARGON2_M_COST");
        const char* env_p = getenv("SECUREFS_ARGON2_P");
        uint32_t t_cost = rounds > 0 ? rounds : 9,
                 m_cost = env_m_cost ? std::stoi(env_m_cost) : (1u << 18u),
                 p = env_p ? std::stoi(env_p) : 4;
        config["iterations"] = t_cost;
        config["argon2_m_cost"] = m_cost;
        config["argon2_p"] = p;
        int rc = argon2id_hash_raw(t_cost,
                                   m_cost,
                                   p,
                                   password,
                                   pass_len,
                                   effective_salt.data(),
                                   effective_salt.size(),
                                   password_derived_key.data(),
                                   password_derived_key.size());
        if (rc)
        {
            throw_runtime_error("Argon2 hashing failed with status code " + std::to_string(rc));
        }
    }
    else
    {
        throw_runtime_error("Unknown pbkdf algorithm " + pbkdf_algorithm);
    }
    config["pbkdf"] = pbkdf_algorithm;
    config["salt"] = hexify(salt);

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    generate_random(iv, array_length(iv));

    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(
        password_derived_key.data(), password_derived_key.size(), iv, array_length(iv));
    encryptor.EncryptAndAuthenticate(
        encrypted_master_key.data(),
        mac,
        array_length(mac),
        iv,
        array_length(iv),
        reinterpret_cast<const byte*>(get_version_header(fsconfig.version)),
        strlen(get_version_header(fsconfig.version)),
        fsconfig.master_key.data(),
        fsconfig.master_key.size());

    Json::Value encrypted_key;
    encrypted_key["IV"] = hexify(iv, array_length(iv));
    encrypted_key["MAC"] = hexify(mac, array_length(mac));
    encrypted_key["key"] = hexify(encrypted_master_key);

    config["encrypted_key"] = std::move(encrypted_key);

    if (fsconfig.version >= 2)
    {
        config["block_size"] = fsconfig.block_size;
        config["iv_size"] = fsconfig.iv_size;
    }
    if (fsconfig.max_padding > 0)
    {
        config["max_padding"] = fsconfig.max_padding;
    }
    if (fsconfig.long_name_component)
    {
        config["long_name_component"] = true;
    }
    return config;
}

void compute_password_derived_key(const Json::Value& config,
                                  const void* password,
                                  size_t pass_len,
                                  key_type& salt,
                                  key_type& password_derived_key)
{
    unsigned iterations = config["iterations"].asUInt();
    std::string pbkdf_algorithm = config.get("pbkdf", PBKDF_ALGO_PKCS5).asString();
    VERBOSE_LOG("Setting the password key derivation function to %s", pbkdf_algorithm);

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        pbkdf_hmac_sha256(password,
                          pass_len,
                          salt.data(),
                          salt.size(),
                          iterations,
                          0,
                          password_derived_key.data(),
                          password_derived_key.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        auto r = config["scrypt_r"].asUInt();
        auto p = config["scrypt_p"].asUInt();
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(password_derived_key.data(),
                         password_derived_key.size(),
                         static_cast<const byte*>(password),
                         pass_len,
                         salt.data(),
                         salt.size(),
                         iterations,
                         r,
                         p);
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_ARGON2ID)
    {
        auto m_cost = config["argon2_m_cost"].asUInt();
        auto p = config["argon2_p"].asUInt();
        int rc = argon2id_hash_raw(iterations,
                                   m_cost,
                                   p,
                                   password,
                                   pass_len,
                                   salt.data(),
                                   salt.size(),
                                   password_derived_key.data(),
                                   password_derived_key.size());
        if (rc)
        {
            throw_runtime_error("Argon2 hashing failed with status code " + std::to_string(rc));
        }
    }
    else
    {
        throw_runtime_error("Unknown pbkdf algorithm " + pbkdf_algorithm);
    }
}

FSConfig parse_config(const Json::Value& config,
                      StringRef maybe_key_file_path,
                      const void* password,
                      size_t pass_len)
{
    using namespace securefs;
    FSConfig fsconfig{};

    fsconfig.version = config["version"].asUInt();
    fsconfig.max_padding = config.get("max_padding", 0u).asUInt();
    fsconfig.long_name_component = config.get("long_name_component", false).asBool();

    if (fsconfig.version == 1)
    {
        fsconfig.block_size = 4096;
        fsconfig.iv_size = 32;
    }
    else if (fsconfig.version == 2 || fsconfig.version == 3 || fsconfig.version == 4)
    {
        fsconfig.block_size = config["block_size"].asUInt();
        fsconfig.iv_size = config["iv_size"].asUInt();
    }
    else
    {
        throwInvalidArgumentException(absl::StrFormat("Unsupported version %u", fsconfig.version));
    }

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt;
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
    fsconfig.master_key.resize(encrypted_key.size());

    auto decrypt_and_verify = [&](const securefs::key_type& wrapping_key) -> bool
    {
        CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(wrapping_key.data(), wrapping_key.size(), iv, array_length(iv));
        return decryptor.DecryptAndVerify(
            fsconfig.master_key.data(),
            mac,
            array_length(mac),
            iv,
            array_length(iv),
            reinterpret_cast<const byte*>(get_version_header(fsconfig.version)),
            strlen(get_version_header(fsconfig.version)),
            encrypted_key.data(),
            encrypted_key.size());
    };

    {
        securefs::key_type new_salt;
        hmac_sha256(salt, maybe_key_file_path, new_salt);

        securefs::key_type password_derived_key;
        compute_password_derived_key(config, password, pass_len, new_salt, password_derived_key);
        if (decrypt_and_verify(password_derived_key))
        {
            return fsconfig;
        }
    }

    // `securefs` used to derive keyfile based key in another way. Try it here for compatibility.
    {
        securefs::key_type wrapping_key;
        securefs::key_type password_derived_key;
        compute_password_derived_key(config, password, pass_len, salt, password_derived_key);
        hmac_sha256(password_derived_key, maybe_key_file_path, wrapping_key);
        if (decrypt_and_verify(wrapping_key))
        {
            return fsconfig;
        }
    }
    throw std::runtime_error("Invalid password or keyfile combination");
}
}    // namespace

namespace securefs
{

std::shared_ptr<FileStream> CommandBase::open_config_stream(const std::string& path, int flags)
{
    return OSService::get_default().open_file_stream(path, flags, 0644);
}

FSConfig CommandBase::read_config(FileStream* stream,
                                  const void* password,
                                  size_t pass_len,
                                  StringRef maybe_key_file_path)
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

    Json::Value value;
    std::string error_message;
    if (!create_json_reader()->parse(str.data(), str.data() + str.size(), &value, &error_message))
        throw_runtime_error(absl::StrFormat("Failure to parse the config file: %s", error_message));

    return parse_config(value, maybe_key_file_path, password, pass_len);
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
                               StringRef maybe_key_file_path,
                               const std::string& pbdkf_algorithm,
                               const FSConfig& config,
                               const void* password,
                               size_t pass_len,
                               unsigned rounds)
{
    key_type salt;
    generate_random(salt.data(), salt.size());
    auto str = generate_config(
                   pbdkf_algorithm, maybe_key_file_path, salt, password, pass_len, rounds, config)
                   .toStyledString();
    stream->sequential_write(str.data(), str.size());
}

/// A base class for all commands that require a data dir to be present.
class _DataDirCommandBase : public CommandBase
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

protected:
    std::string get_real_config_path()
    {
        return !config_path.getValue().empty()
            ? config_path.getValue()
            : data_dir.getValue() + PATH_SEPARATOR_CHAR + CONFIG_FILE_NAME;
    }
};

static void secure_wipe(const char* buffer, size_t size)
{
    // On FreeBSD, this may be called. It is a no-op because we cannot write const region.
}

static void secure_wipe(char* buffer, size_t size)
{
    CryptoPP::SecureWipeBuffer(reinterpret_cast<byte*>(buffer), size);
}

void CommandBase::parse_cmdline(int argc, const char* const* argv) { cmdline()->parse(argc, argv); }

class _SinglePasswordCommandBase : public _DataDirCommandBase
{
protected:
    TCLAP::ValueArg<std::string> pass{
        "",
        "pass",
        "Password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "password"};
    TCLAP::ValueArg<std::string> keyfile{
        "",
        "keyfile",
        "An optional path to a key file to use in addition to or in place of password",
        false,
        "",
        "path"};
    TCLAP::SwitchArg askpass{
        "",
        "askpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        false};
    CryptoPP::AlignedSecByteBlock password;

    void get_password(bool require_confirmation)
    {
        if (pass.isSet() && !pass.getValue().empty())
        {
            password.Assign(reinterpret_cast<const byte*>(pass.getValue().data()),
                            pass.getValue().size());
            secure_wipe(&pass.getValue()[0], pass.getValue().size());
            return;
        }
        if (keyfile.isSet() && !keyfile.getValue().empty() && !askpass.getValue())
        {
            password.Assign(reinterpret_cast<const byte*>(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED),
                            strlen(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED));
            return;
        }
        if (require_confirmation)
        {
            return OSService::read_password_with_confirmation("Enter password:", &password);
        }
        return OSService::read_password_no_confirmation("Enter password:", &password);
    }

    void add_all_args_from_base(TCLAP::CmdLine& cmd_line)
    {
        cmd_line.add(&data_dir);
        cmd_line.add(&config_path);
        cmd_line.add(&pass);
        cmd_line.add(&keyfile);
        cmd_line.add(&askpass);
    }
};

static const std::string message_for_setting_pbkdf = absl::StrFormat(
    "The algorithm to stretch passwords. Use %s for maximum protection (default), or "
    "%s for compatibility with old versions of securefs",
    PBKDF_ALGO_ARGON2ID,
    PBKDF_ALGO_PKCS5);

class CreateCommand : public _SinglePasswordCommandBase
{
private:
    TCLAP::ValueArg<unsigned> rounds{
        "r",
        "rounds",
        "Specify how many rounds of key derivation are applied (0 for automatic)",
        false,
        0,
        "integer"};
    TCLAP::ValueArg<unsigned int> format{
        "", "format", "The filesystem format version (1,2,3,4)", false, 4, "integer"};
    TCLAP::ValueArg<unsigned int> iv_size{
        "", "iv-size", "The IV size (ignored for fs format 1)", false, 12, "integer"};
    TCLAP::ValueArg<unsigned int> block_size{
        "", "block-size", "Block size for files (ignored for fs format 1)", false, 4096, "integer"};
    TCLAP::SwitchArg store_time{
        "",
        "store_time",
        "alias for \"--format 3\", enables the extension where timestamp are stored and encrypted"};
    TCLAP::ValueArg<std::string> pbkdf{
        "", "pbkdf", message_for_setting_pbkdf, false, PBKDF_ALGO_ARGON2ID, "string"};
    TCLAP::ValueArg<unsigned> max_padding{
        "",
        "max-padding",
        "Maximum number of padding (the unit is byte) to add to all files in order to obfuscate "
        "their sizes. Each "
        "file has a different padding. Enabling this has a large performance cost.",
        false,
        0,
        "int"};

public:
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        auto result = make_unique<TCLAP::CmdLine>(help_message());
        add_all_args_from_base(*result);
        result->add(&iv_size);
        result->add(&rounds);
        result->add(&format);
        result->add(&store_time);
        result->add(&block_size);
        result->add(&pbkdf);
        result->add(&max_padding);
        return result;
    }

    void parse_cmdline(int argc, const char* const* argv) override
    {
        _SinglePasswordCommandBase::parse_cmdline(argc, argv);
        get_password(true);
    }

    int execute() override
    {
        if (format.isSet() && store_time.isSet())
        {
            absl::FPrintF(stderr,
                          "Conflicting flags --format and --store_time are specified together\n");
            return 1;
        }

        if (format.isSet() && format.getValue() == 1 && (iv_size.isSet() || block_size.isSet()))
        {
            absl::FPrintF(stderr,
                          "IV and block size options are not available for filesystem format 1\n");
            return 1;
        }

        unsigned format_version = store_time.isSet() ? 3 : format.getValue();

        OSService::get_default().ensure_directory(data_dir.getValue(), 0755);

        FSConfig config;
        config.master_key.resize(format_version < 4 ? KEY_LENGTH : 4 * KEY_LENGTH);
        CryptoPP::OS_GenerateRandomBlock(false, config.master_key.data(), config.master_key.size());

        config.iv_size = format_version == 1 ? 32 : iv_size.getValue();
        config.version = format_version;
        config.block_size = block_size.getValue();
        config.max_padding = max_padding.getValue();

        auto config_stream
            = open_config_stream(get_real_config_path(), O_WRONLY | O_CREAT | O_EXCL);
        DEFER(if (has_uncaught_exceptions()) {
            OSService::get_default().remove_file(get_real_config_path());
        });
        write_config(config_stream.get(),
                     keyfile.getValue(),
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
            auto& root_fp = *root;
            FileLockGuard file_lock_guard(root_fp);
            root_fp.set_uid(securefs::OSService::getuid());
            root_fp.set_gid(securefs::OSService::getgid());
            root_fp.set_mode(S_IFDIR | 0755);
            root_fp.set_nlink(1);
            root_fp.flush();
        }
        return 0;
    }

    const char* long_name() const noexcept override { return "create"; }

    char short_name() const noexcept override { return 'c'; }

    const char* help_message() const noexcept override { return "Create a new filesystem"; }
};

class ChangePasswordCommand : public _DataDirCommandBase
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
        "", "pbkdf", message_for_setting_pbkdf, false, PBKDF_ALGO_ARGON2ID, "string"};
    TCLAP::ValueArg<std::string> old_key_file{
        "", "oldkeyfile", "Path to original key file", false, "", "path"};
    TCLAP::ValueArg<std::string> new_key_file{
        "", "newkeyfile", "Path to new key file", false, "", "path"};
    TCLAP::SwitchArg askoldpass{
        "",
        "askoldpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        false};
    TCLAP::SwitchArg asknewpass{
        "",
        "asknewpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        false};
    TCLAP::ValueArg<std::string> oldpass{
        "",
        "oldpass",
        "The old password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "string"};
    TCLAP::ValueArg<std::string> newpass{
        "",
        "newpass",
        "The new password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "string"};

    static void assign(StringRef value, CryptoPP::AlignedSecByteBlock& output)
    {
        output.Assign(reinterpret_cast<const byte*>(value.data()), value.size());
    }

public:
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        auto result = make_unique<TCLAP::CmdLine>(help_message());
        result->add(&data_dir);
        result->add(&rounds);
        result->add(&config_path);
        result->add(&old_key_file);
        result->add(&new_key_file);
        result->add(&askoldpass);
        result->add(&asknewpass);
        result->add(&oldpass);
        result->add(&newpass);
        result->add(&pbkdf);
        return result;
    }

    void parse_cmdline(int argc, const char* const* argv) override
    {
        _DataDirCommandBase::parse_cmdline(argc, argv);

        if (oldpass.isSet())
        {
            assign(oldpass.getValue(), old_password);
        }
        else if (old_key_file.getValue().empty() || askoldpass.getValue())
        {
            OSService::read_password_no_confirmation("Old password: ", &old_password);
        }
        else
        {
            assign(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED, old_password);
        }

        if (newpass.isSet())
        {
            assign(newpass.getValue(), new_password);
        }
        else if (new_key_file.getValue().empty() || asknewpass.getValue())
        {
            OSService::read_password_with_confirmation("New password: ", &new_password);
        }
        else
        {
            assign(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED, new_password);
        }
    }

    int execute() override
    {
        auto original_path = get_real_config_path();
        byte buffer[16];
        generate_random(buffer, array_length(buffer));
        auto tmp_path = original_path + hexify(buffer, array_length(buffer));
        auto stream = OSService::get_default().open_file_stream(original_path, O_RDONLY, 0644);
        auto config = read_config(
            stream.get(), old_password.data(), old_password.size(), old_key_file.getValue());
        stream = OSService::get_default().open_file_stream(
            tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        DEFER(if (has_uncaught_exceptions()) {
            OSService::get_default().remove_file_nothrow(tmp_path);
        });
        write_config(stream.get(),
                     new_key_file.getValue(),
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
        return "Change password/keyfile of existing filesystem";
    }
};

class MountCommand : public _SinglePasswordCommandBase
{
private:
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
    TCLAP::ValueArg<std::string> fsname{
        "", "fsname", "Filesystem name shown when mounted", false, "securefs", "fsname"};
    TCLAP::ValueArg<std::string> fssubtype{
        "", "fssubtype", "Filesystem subtype shown when mounted", false, "securefs", "fssubtype"};
    TCLAP::SwitchArg noflock{"",
                             "noflock",
                             "Disables the usage of file locking. Needed on some network "
                             "filesystems. May cause data loss, so use it at your own risk!",
                             false};
    TCLAP::ValueArg<std::string> normalization{"",
                                               "normalization",
                                               "Mode of filename normalization. Valid values: "
                                               "none, casefold, nfc, casefold+nfc. Defaults to nfc "
                                               "on macOS and none on other platforms",
                                               false,
#ifdef __APPLE__
                                               "nfc",
#else
                                               "none",
#endif
                                               ""};
    TCLAP::ValueArg<int> attr_timeout{"",
                                      "attr-timeout",
                                      "Number of seconds to cache file attributes. Default is 30.",
                                      false,
                                      30,
                                      "int"};
    TCLAP::SwitchArg skip_dot_dot{"",
                                  "skip-dot-dot",
                                  "When enabled, securefs will not return . and .. in `readdir` "
                                  "calls. You should normally not need this.",
                                  false};
    TCLAP::SwitchArg plain_text_names{"",
                                      "plain-text-names",
                                      "When enabled, securefs does not encrypt or decrypt file "
                                      "names. Use it at your own risk. No effect on full format.",
                                      false};

private:
    std::vector<const char*> to_c_style_args(const std::vector<std::string>& args)
    {
        std::vector<const char*> result(args.size());
        std::transform(args.begin(),
                       args.end(),
                       result.begin(),
                       [](const std::string& s) { return s.c_str(); });
        return result;
    }
#ifdef WIN32
    static bool is_letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
    static bool is_drive_mount(StringRef mount_point)
    {
        return mount_point.size() == 2 && is_letter(mount_point[0]) && mount_point[1] == ':';
    }
    static bool is_network_mount(StringRef mount_point)
    {
        return mount_point.starts_with("\\\\") && !mount_point.starts_with("\\\\?\\");
    }
#endif

    static std::string escape_args(const std::vector<std::string>& args)
    {
        std::string result;
        for (const auto& a : args)
        {
            result.append(securefs::escape_nonprintable(a.data(), a.size()));
            result.push_back(' ');
        }
        if (!result.empty())
        {
            result.pop_back();
        }
        return result;
    }

public:
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        auto result = make_unique<TCLAP::CmdLine>(help_message());
        add_all_args_from_base(*result);
        result->add(&background);
        // result->add(&insecure);
        result->add(&verbose);
        result->add(&trace);
        result->add(&log);
        result->add(&mount_point);
        result->add(&fuse_options);
        result->add(&single_threaded);
        result->add(&normalization);
        result->add(&fsname);
        result->add(&fssubtype);
        result->add(&noflock);
        result->add(&attr_timeout);
        result->add(&skip_dot_dot);
        result->add(&plain_text_names);
#ifdef __APPLE__
        result->add(&noxattr);
#endif
        return result;
    }

    void parse_cmdline(int argc, const char* const* argv) override
    {
        _SinglePasswordCommandBase::parse_cmdline(argc, argv);

        get_password(false);

        if (global_logger && verbose.getValue())
            global_logger->set_level(kLogVerbose);
        if (global_logger && trace.getValue())
            global_logger->set_level(kLogTrace);

        set_lock_enabled(!noflock.getValue());
        if (noflock.getValue() && !single_threaded.getValue())
        {
            WARN_LOG("Using --noflock without --single is highly dangerous");
        }
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
        bool network_mount = is_network_mount(mount_point.getValue());
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
        auto config = read_config(
            config_stream.get(), password.data(), password.size(), keyfile.getValue());
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

        std::vector<std::string> fuse_args{
            "securefs",
            "-o",
            "hard_remove",
            "-o",
            "fsname=" + fsname.getValue(),
            "-o",
            "subtype=" + fssubtype.getValue(),
            "-o",
            absl::StrFormat("entry_timeout=%d", attr_timeout.getValue()),
            "-o",
            absl::StrFormat("attr_timeout=%d", attr_timeout.getValue()),
            "-o",
            absl::StrFormat("negative_timeout=%d", attr_timeout.getValue()),
#ifndef _WIN32
            "-o",
            "atomic_o_trunc",
#endif
        };
        if (single_threaded.getValue())
        {
            fuse_args.emplace_back("-s");
        }
        else
        {
#ifdef _WIN32
            fuse_args.emplace_back("-o");
            fuse_args.emplace_back(
                absl::StrFormat("ThreadCount=%d", 2 * std::thread::hardware_concurrency()));
#endif
        }
        if (!background.getValue())
            fuse_args.emplace_back("-f");

#ifdef __APPLE__
        const char* copyfile_disable = ::getenv("COPYFILE_DISABLE");
        if (copyfile_disable)
        {
            VERBOSE_LOG("Mounting without .DS_Store and other apple dot files because "
                        "environmental "
                        "variable COPYFILE_DISABLE is set to \"%s\"",
                        copyfile_disable);
            fuse_args.emplace_back("-o");
            fuse_args.emplace_back("noappledouble");
        }
#elif _WIN32
        fuse_args.emplace_back("-ouid=-1,gid=-1,umask=0");
        if (network_mount)
        {
            fuse_args.emplace_back("--VolumePrefix=" + mount_point.getValue().substr(1));
        }
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(
            absl::StrFormat("FileInfoTimeout=%d", attr_timeout.getValue() * 1000));
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(
            absl::StrFormat("DirInfoTimeout=%d", attr_timeout.getValue() * 1000));
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(absl::StrFormat("EaTimeout=%d", attr_timeout.getValue() * 1000));
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back(
            absl::StrFormat("VolumeInfoTimeout=%d", attr_timeout.getValue() * 1000));
#else
        fuse_args.emplace_back("-o");
        fuse_args.emplace_back("big_writes");
#endif
        if (fuse_options.isSet())
        {
            for (const std::string& opt : fuse_options.getValue())
            {
                fuse_args.emplace_back("-o");
                fuse_args.emplace_back(opt);
            }
        }

#ifdef WIN32
        if (!network_mount)
#endif
            fuse_args.emplace_back(mount_point.getValue());

        VERBOSE_LOG("Filesystem parameters: format version %d, block size %u (bytes), iv size %u "
                    "(bytes)",
                    config.version,
                    config.block_size,
                    config.iv_size);

        if (!is_vulnerable)
        {
            VERBOSE_LOG("Master key: %s", hexify(config.master_key));
        }

        operations::MountOptions fsopt;
        fsopt.root = std::make_shared<OSService>(data_dir.getValue());
        fsopt.block_size = config.block_size;
        fsopt.iv_size = config.iv_size;
        fsopt.version = config.version;
        fsopt.master_key = config.master_key;
        fsopt.flags = config.version != 3 ? 0 : kOptionStoreTime;
        fsopt.max_padding_size = config.max_padding;
        if (insecure.getValue())
            fsopt.flags.value() |= kOptionNoAuthentication;
        bool case_insensitive = false;
        bool enable_nfc = false;
        if (normalization.getValue() == "nfc")
        {
            enable_nfc = true;
        }
        else if (normalization.getValue() == "casefold")
        {
            case_insensitive = true;
        }
        else if (normalization.getValue() == "casefold+nfc")
        {
            case_insensitive = true;
            enable_nfc = true;
        }
        else if (normalization.getValue() != "none")
        {
            throw_runtime_error("Invalid flag of --normalization: " + normalization.getValue());
        }
        if (case_insensitive)
        {
            INFO_LOG("Mounting as a case insensitive filesystem");
            fsopt.flags.value() |= kOptionCaseFoldFileName;
        }
        if (enable_nfc)
        {
            INFO_LOG("Mounting as a Unicode normalized filesystem");
            fsopt.flags.value() |= kOptionNFCFileName;
        }
        if (skip_dot_dot.getValue())
        {
            fsopt.flags.value() |= kOptionSkipDotDot;
        }
        if (plain_text_names.getValue())
        {
            if (config_path.getValue().empty())
            {
                WARN_LOG("--plain-text-names should be used with out of tree JSON config. Please "
                         "specify --config-path explicitly.");
            }
            fsopt.flags.value() |= kOptionNoNameTranslation;
        }
        if (config.long_name_component)
        {
            fsopt.flags.value() |= kOptionLongNameComponent;
        }

        if (config.version < 4)
        {
            try
            {
                fsopt.lock_stream = fsopt.root->open_file_stream(
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
                absl::FPrintf(stderr,
                              "Warning: %s has no extended attribute support.\nXattr is disabled\n",
                              data_dir.getValue());
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
        VERBOSE_LOG("Calling fuse_main with arguments: %s", escape_args(fuse_args));
        recreate_logger();
        return fuse_main(static_cast<int>(fuse_args.size()),
                         const_cast<char**>(to_c_style_args(fuse_args).data()),
                         &operations,
                         &fsopt);
    }

    const char* long_name() const noexcept override { return "mount"; }

    char short_name() const noexcept override { return 'm'; }

    const char* help_message() const noexcept override { return "Mount an existing filesystem"; }
};

class FixCommand : public _SinglePasswordCommandBase
{
public:
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        auto result = make_unique<TCLAP::CmdLine>(help_message());
        add_all_args_from_base(*result);
        return result;
    }

    void parse_cmdline(int argc, const char* const* argv) override
    {
        _SinglePasswordCommandBase::parse_cmdline(argc, argv);

        fflush(stdout);
        fflush(stderr);
        puts("You should backup your repository before running this command. Are you sure you want "
             "to continue? (yes/no)");
        fflush(stdout);
        char answer[100] = {};
        if (fgets(answer, 100, stdin) == nullptr)
        {
            THROW_POSIX_EXCEPTION(errno, "fgets");
        }
        if (strcmp(answer, "yes\n") != 0)
        {
            throw_runtime_error("User aborted operation");
        }
        get_password(false);
    }

    int execute() override
    {
        auto config_stream = open_config_stream(get_real_config_path(), O_RDONLY);
        auto config = read_config(
            config_stream.get(), password.data(), password.size(), keyfile.getValue());
        config_stream.reset();

        if (config.version >= 4)
        {
            absl::FPrintF(stderr,
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
        fsopt.flags = config.version != 3 ? 0 : kOptionStoreTime;

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
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        auto result = make_unique<TCLAP::CmdLine>(help_message());
        return result;
    }

    int execute() override
    {
        using namespace CryptoPP;
        absl::PrintF("securefs %s\n", GIT_VERSION);
        absl::PrintF("Crypto++ %g\n", CRYPTOPP_VERSION / 100.0);
#ifdef WIN32
        HMODULE hd = GetModuleHandleW((sizeof(void*) == 8) ? L"winfsp-x64.dll" : L"winfsp-x86.dll");
        NTSTATUS(*fsp_version_func)
        (uint32_t*) = get_proc_address<decltype(fsp_version_func)>(hd, "FspVersion");
        if (fsp_version_func)
        {
            uint32_t vn;
            if (fsp_version_func(&vn) == 0)
            {
                absl::PrintF("WinFsp %u.%u\n", vn >> 16, vn & 0xFFFFu);
            }
        }
#else
        typedef int version_function(void);
        auto fuse_version_func
            = reinterpret_cast<version_function*>(::dlsym(RTLD_DEFAULT, "fuse_version"));
        absl::PrintF("libfuse %d\n", fuse_version_func());
#endif

        absl::PrintF("utf8proc %s\n", utf8proc_version());

#ifdef CRYPTOPP_DISABLE_ASM
        fputs("\nBuilt without hardware acceleration\n", stdout);
#else
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        absl::PrintF("\nHardware features available:\nSSE2: %s\nSSE3: %s\nSSE4.1: %s\nSSE4.2: "
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
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        auto result = make_unique<TCLAP::CmdLine>(help_message());
        result->add(&path);
        return result;
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
            ERROR_LOG("The path %s does not exist.", path.getValue());
        }

        std::string real_config_path = path.getValue();
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            real_config_path.append("/.securefs.json");
        fs = OSService::get_default().open_file_stream(real_config_path, O_RDONLY, 0);

        Json::Value config_json;

        // Open a new scope to limit the lifetime of `buffer`.
        {
            std::vector<char> buffer(fs->size(), 0);
            fs->read(buffer.data(), 0, buffer.size());
            std::string error_message;
            if (!create_json_reader()->parse(
                    buffer.data(), buffer.data() + buffer.size(), &config_json, &error_message))
            {
                throw_runtime_error(
                    absl::StrFormat("Failure to parse the config file: %s", error_message));
            }
        }

        unsigned format_version = config_json["version"].asUInt();
        if (format_version < 1 || format_version > 4)
        {
            ERROR_LOG("Unknown filesystem format version %u", format_version);
            return 44;
        }
        absl::PrintF("Config file path: %s\n", real_config_path);
        absl::PrintF("Filesystem format version: %u\n", format_version);
        absl::PrintF("Is full or lite format: %s\n", (format_version < 4) ? "full" : "lite");
        absl::PrintF("Is underlying directory flattened: %v\n", format_version < 4);
        absl::PrintF("Is multiple mounts allowed: %v\n", format_version >= 4);
        absl::PrintF("Is timestamp stored within the fs: %v\n\n", format_version == 3);

        absl::PrintF("Content block size: %u bytes\n",
                     format_version == 1 ? 4096 : config_json["block_size"].asUInt());
        absl::PrintF("Content IV size: %u bits\n",
                     format_version == 1 ? 256 : config_json["iv_size"].asUInt() * 8);
        absl::PrintF("Password derivation algorithm: %s\n",
                     config_json.get("pbkdf", PBKDF_ALGO_PKCS5).asCString());
        absl::PrintF("Password derivation iterations: %u\n", config_json["iterations"].asUInt());
        absl::PrintF("Per file key generation algorithm: %s\n",
                     format_version < 4 ? "HMAC-SHA256" : "AES");
        absl::PrintF("Content cipher: %s\n", format_version < 4 ? "AES-256-GCM" : "AES-128-GCM");
        absl::PrintF("Maximum padding to obfuscate file sizes: %u byte(s)\n",
                     config_json.get("max_padding", 0u).asUInt());
        return 0;
    }
};

class DocCommand : public CommandBase
{
private:
    std::vector<CommandBase*> commands{};

public:
    DocCommand() = default;
    ~DocCommand() = default;
    const char* long_name() const noexcept override { return "doc"; }
    char short_name() const noexcept override { return 0; }
    const char* help_message() const noexcept override
    {
        return "Display the full help message of all commands in markdown format";
    }
    std::unique_ptr<TCLAP::CmdLine> cmdline() override
    {
        return make_unique<TCLAP::CmdLine>(help_message());
    }
    void add_command(CommandBase* c) { commands.push_back(c); }
    int execute() override
    {
        fputs("# securefs\n", stdout);
        fputs("The command strucuture is `securefs ${SUBCOMMAND} ${SUBOPTIONS}`.\nSee below for "
              "available subcommands and relevant options\n\n",
              stdout);
        for (auto c : commands)
        {
            if (c->short_name())
                absl::PrintF("## %s (short name: %c)\n", c->long_name(), c->short_name());
            else
                absl::PrintF("## %s\n", c->long_name());
            absl::PrintF("%s\n\n", c->help_message());
            auto cmdline = c->cmdline();

            std::vector<std::pair<size_t, TCLAP::Arg*>> prioritizedArgs;
            size_t index = 0;
            for (TCLAP::Arg* arg : cmdline->getArgList())
            {
                ++index;
                if (dynamic_cast<TCLAP::UnlabeledValueArg<std::string>*>(arg))
                {
                    prioritizedArgs.emplace_back(index, arg);
                }
                else
                {
                    prioritizedArgs.emplace_back(2 * cmdline->getArgList().size() - index, arg);
                }
            }
            std::sort(prioritizedArgs.begin(), prioritizedArgs.end());

            for (auto&& pair : prioritizedArgs)
            {
                TCLAP::Arg* arg = pair.second;
                {
                    auto a = dynamic_cast<TCLAP::UnlabeledValueArg<std::string>*>(arg);
                    if (a)
                    {
                        absl::PrintF(
                            "- **%s**: (*positional*) %s\n", a->getName(), a->getDescription());
                        continue;
                    }
                }
                if (arg->getName() == "ignore_rest" || arg->getName() == "version"
                    || arg->getName() == "help")
                {
                    continue;
                }
                fputs("- ", stdout);
                auto flag = arg->getFlag();
                if (!flag.empty())
                {
                    absl::PrintF("**%c%s** or ", arg->flagStartChar(), flag);
                }
                absl::PrintF("**%s%s**", arg->nameStartString(), arg->getName());
                absl::PrintF(": %s. ", arg->getDescription());
                {
                    auto a = dynamic_cast<TCLAP::SwitchArg*>(arg);
                    if (a)
                    {
                        if (a->getValue())
                        {
                            fputs("*This is a switch arg. Default: true.*\n", stdout);
                        }
                        else
                        {
                            fputs("*This is a switch arg. Default: false.*\n", stdout);
                        }
                        continue;
                    }
                }
                {
                    auto a = dynamic_cast<TCLAP::ValueArg<std::string>*>(arg);
                    if (a)
                    {
                        if (a->getValue().empty())
                        {
                            fputs("*Unset by default.*\n", stdout);
                        }
                        else
                        {
                            absl::PrintF("*Default: %s.*\n", a->getValue());
                        }
                        continue;
                    }
                }
                {
                    auto a = dynamic_cast<TCLAP::ValueArg<unsigned>*>(arg);
                    if (a)
                    {
                        absl::PrintF("*Default: %u.*\n", a->getValue());
                        continue;
                    }
                }
                {
                    auto a = dynamic_cast<TCLAP::ValueArg<int>*>(arg);
                    if (a)
                    {
                        absl::PrintF("*Default: %d.*\n", a->getValue());
                        continue;
                    }
                }
                {
                    auto a = dynamic_cast<TCLAP::MultiArg<std::string>*>(arg);
                    if (a)
                    {
                        fputs("*This option can be specified multiple times.*\n", stdout);
                        continue;
                    }
                }
                throw_runtime_error(std::string("Unknown type of arg ") + typeid(*arg).name());
            }
        }
        return 0;
    }
};

int commands_main(int argc, const char* const* argv)
{
    try
    {
        std::ios_base::sync_with_stdio(false);
        std::unique_ptr<CommandBase> cmds[] = {make_unique<MountCommand>(),
                                               make_unique<CreateCommand>(),
                                               make_unique<ChangePasswordCommand>(),
                                               make_unique<FixCommand>(),
                                               make_unique<VersionCommand>(),
                                               make_unique<InfoCommand>(),
                                               make_unique<DocCommand>()};

        const char* const program_name = argv[0];
        auto doc_command = dynamic_cast<DocCommand*>(cmds[array_length(cmds) - 1].get());
        for (auto&& c : cmds)
        {
            doc_command->add_command(c.get());
        }

        auto print_usage = [&]()
        {
            fputs("Available subcommands:\n\n", stderr);

            for (auto&& command : cmds)
            {
                if (command->short_name())
                {
                    absl::FPrintF(stderr,
                                  "%s (alias: %c): %s\n",
                                  command->long_name(),
                                  command->short_name(),
                                  command->help_message());
                }
                else
                {
                    absl::FPrintF(
                        stderr, "%s: %s\n", command->long_name(), command->help_message());
                }
            }

            absl::FPrintF(stderr, "\nType %s ${SUBCOMMAND} --help for details\n", program_name);
            return 1;
        };

        if (argc < 2)
            return print_usage();
        argc--;
        argv++;

        for (auto&& command : cmds)
        {
            if (strcmp(argv[0], command->long_name()) == 0
                || (argv[0] != nullptr && argv[0][0] == command->short_name() && argv[0][1] == 0))
            {
                command->parse_cmdline(argc, argv);
                return command->execute();
            }
        }
        return print_usage();
    }
    catch (const TCLAP::ArgException& e)
    {
        ERROR_LOG("Error parsing arguments: %s at %s\n", e.error(), e.argId());
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
