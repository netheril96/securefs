#include "commands.h"
#include "btree_dir.h"
#include "crypto.h"
#include "exceptions.h"
#include "files.h"
#include "full_format.h"
#include "fuse2_workaround.h"
#include "fuse_high_level_ops_base.h"
#include "fuse_hook.h"
#include "git-version.h"
#include "internal_mount.h"
#include "lite_format.h"
#include "lock_enabled.h"
#include "logger.h"
#include "myutils.h"
#include "object.h"
#include "params.pb.h"
#include "params_io.h"
#include "platform.h"
#include "tags.h"

#include <absl/strings/escaping.h>
#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/synchronization/mutex.h>
#include <absl/time/time.h>
#include <argon2.h>
#include <chrono>
#include <cryptopp/cpu.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/secblock.h>
#include <google/protobuf/util/json_util.h>
#include <optional>
#include <sys/stat.h>
#include <tclap/CmdLine.h>
#include <tclap/SwitchArg.h>
#include <tclap/ValueArg.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <string_view>
#include <thread>
#include <typeinfo>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#include <winfsp/winfsp.h>
#endif

#if __has_include(<sys/vfs.h>)
#include <sys/vfs.h>
#endif
#if __has_include(<sys/statfs.h>)
#include <sys/statfs.h>
#endif

using namespace securefs;

namespace
{
constexpr std::string_view const kLegacyConfigFileName = ".securefs.json";
constexpr std::string_view const kConfigFileName = ".config.pb";
constexpr std::string_view EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED = " ";
}    // namespace

namespace securefs
{
struct ArgsHolder : public Object
{
public:
    explicit ArgsHolder(TCLAP::CmdLine& cmdline) : cmdline(cmdline) {}

protected:
    TCLAP::CmdLine& cmdline;
};

struct DataDirHolder : public ArgsHolder
{
    using ArgsHolder::ArgsHolder;

    TCLAP::UnlabeledValueArg<std::string> data_dir{
        "dir", "Directory where the data are stored", true, "", "data_dir", cmdline};
    TCLAP::ValueArg<std::string> config_path{
        "",
        "config",
        "Full path name of the config file. ${data_dir}/.config.pb by default",
        false,
        "",
        "config_path",
        cmdline};

    std::string get_real_config_path_for_reading()
    {
        if (!config_path.getValue().empty())
        {
            return config_path.getValue();
        }
        OSService root(data_dir.getValue());
        fuse_stat st{};
        if (root.stat(std::string(kConfigFileName), &st))
        {
            return root.norm_path_narrowed(kConfigFileName);
        }
        if (root.stat(std::string(kLegacyConfigFileName), &st))
        {
            return root.norm_path_narrowed(kLegacyConfigFileName);
        }
        throw_runtime_error("No params file found. Please verify if the data dir is correct, or if "
                            "you should manually specify the params file.");
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

void CommandBase::parse_cmdline(int argc, const char* const* argv) { cmdline().parse(argc, argv); }

struct SinglePasswordHolder : public DataDirHolder
{
    using DataDirHolder::DataDirHolder;

    TCLAP::ValueArg<std::string> pass{
        "",
        "pass",
        "Password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "password",
        cmdline};
    TCLAP::ValueArg<std::string> keyfile{
        "",
        "keyfile",
        "An optional path to a key file to use in addition to or in place of password",
        false,
        "",
        "path",
        cmdline};
    TCLAP::SwitchArg askpass{
        "",
        "askpass",
        "When provided, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        cmdline,
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
            password.Assign(
                reinterpret_cast<const byte*>(EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED.data()),
                EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED.size());
            return;
        }
        if (require_confirmation)
        {
            return OSService::read_password_with_confirmation("Enter password:", &password);
        }
        return OSService::read_password_no_confirmation("Enter password:", &password);
    }
};

struct Argon2idArgsHolder : public ArgsHolder
{
    using ArgsHolder::ArgsHolder;

    TCLAP::ValueArg<unsigned> t{
        "", "argon2-t", "The time cost for argon2 algorithm", false, 30, "integer", cmdline};
    TCLAP::ValueArg<unsigned> m{"",
                                "argon2-m",
                                "The memory cost for argon2 algorithm (in terms of KiB)",
                                false,
                                1 << 18,
                                "integer",
                                cmdline};
    TCLAP::ValueArg<unsigned> p{
        "", "argon2-p", "The parallelism for argon2 algorithm", false, 4, "integer", cmdline};

    EncryptedSecurefsParams::Argon2idParams to_params()
    {
        EncryptedSecurefsParams::Argon2idParams result;
        result.set_time_cost(t.getValue());
        result.set_memory_cost(m.getValue());
        result.set_parallelism(p.getValue());
        return result;
    }
};

class CreateCommand : public CommandBase
{
private:
    static inline constexpr std::string_view kSensitive = "sensitive", kInsensitive = "insensitive";

    SinglePasswordHolder single_pass_holder_{cmdline()};
    Argon2idArgsHolder argon2id_holder_{cmdline()};

    TCLAP::ValueArg<std::string> format{
        "f",
        "format",
        "The format type of the repository. Either lite or full. Lite repos are faster and more "
        "reliable, but the directory structure itself is visible. Full repos offer more privacy at "
        "the cost of performance and ease of synchronization.",
        false,
        "lite",
        "lite/full",
        cmdline()};
    TCLAP::ValueArg<unsigned int> iv_size{
        "", "iv-size", "The IV size (ignored for fs format 1)", false, 12, "integer", cmdline()};
    TCLAP::ValueArg<unsigned int> block_size{"",
                                             "block-size",
                                             "Block size for files (ignored for fs format 1)",
                                             false,
                                             4096,
                                             "integer",
                                             cmdline()};
    TCLAP::ValueArg<unsigned> max_padding{
        "",
        "max-padding",
        "Maximum number of padding (the unit is byte) to add to all files in order to obfuscate "
        "their sizes. Each "
        "file has a different padding. Enabling this has a large performance cost.",
        false,
        0,
        "int",
        cmdline()};
    TCLAP::ValueArg<unsigned int> long_name_threshold{
        "",
        "long-name-threshold",
        "(For lite format only) when the filename component exceeds this length, it will be stored "
        "encrypted in a SQLite database.",
        false,
        128,
        "integer",
        cmdline()};
    TCLAP::ValueArg<std::string> case_handling{
        "",
        "case",
        "Either sensitive or insensitive. Changes how full format stores its filenames. Not "
        "applicable to lite format.",
        false,
        std::string(kSensitive),
        absl::StrCat(kSensitive, "/", kInsensitive),
        cmdline()};
    TCLAP::ValueArg<std::string> uninorm{
        "",
        "uninorm",
        "Either sensitive or insensitive. Changes how full format stores its filenames. Not "
        "applicable to lite format.",
        false,
        std::string(kSensitive),
        absl::StrCat(kSensitive, "/", kInsensitive),
        cmdline()};

private:
    static void randomize(std::string* str, size_t size)
    {
        str->resize(size);
        generate_random(str->data(), str->size());
    }

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        CommandBase::parse_cmdline(argc, argv);
        single_pass_holder_.get_password(true);
    }

    int execute() override
    {
        OSService::get_default().ensure_directory(single_pass_holder_.data_dir.getValue(), 0755);

        DecryptedSecurefsParams params;
        params.mutable_size_params()->set_iv_size(iv_size.getValue());
        params.mutable_size_params()->set_block_size(block_size.getValue());
        params.mutable_size_params()->set_max_padding_size(max_padding.getValue());

        if (absl::EqualsIgnoreCase(format.getValue(), "lite") || format.getValue() == "4")
        {
            randomize(params.mutable_lite_format_params()->mutable_name_key(), 32);
            randomize(params.mutable_lite_format_params()->mutable_content_key(), 32);
            randomize(params.mutable_lite_format_params()->mutable_xattr_key(), 32);
            randomize(params.mutable_lite_format_params()->mutable_padding_key(), 32);

            if (long_name_threshold.getValue() > 0)
            {
                params.mutable_lite_format_params()->set_long_name_threshold(
                    long_name_threshold.getValue());
            }
        }
        else if (absl::EqualsIgnoreCase(format.getValue(), "full") || format.getValue() == "2")
        {
            randomize(params.mutable_full_format_params()->mutable_master_key(), 32);
            if (case_handling.getValue() == kInsensitive)
            {
                params.mutable_full_format_params()->set_case_insensitive(true);
            }
            else if (case_handling.getValue() != kSensitive)
            {
                throw_runtime_error("Invalid value for --case: " + case_handling.getValue());
            }
            else if (is_windows() && !case_handling.isSet())
            {
                WARN_LOG("It is recommended to add --case %s on Windows for full format "
                         "in order to match the default behavior of NTFS.",
                         kInsensitive);
            }
            if (uninorm.getValue() == kInsensitive)
            {
                params.mutable_full_format_params()->set_unicode_normalization_agnostic(true);
            }
            else if (uninorm.getValue() != kSensitive)
            {
                throw_runtime_error("Invalid value for --uninorm: " + uninorm.getValue());
            }
            else if (is_apple() && !uninorm.isSet())
            {
                WARN_LOG("It is recommended to add --uninorm %s on Apple for full format "
                         "in order to match the default behavior of APFS/HFS+.",
                         kInsensitive);
            }
            if (case_handling.getValue() == kInsensitive && uninorm.getValue() == kInsensitive)
            {
                WARN_LOG("When both --case %s and --uninorm %s is specified, the resulting "
                         "filesystem may encounter problems on Windows.",
                         kInsensitive,
                         kInsensitive);
            }
        }
        else
        {
            throw_runtime_error("--format lite/full must be specified");
        }

        auto encrypted_data
            = encrypt(params,
                      argon2id_holder_.to_params(),
                      {single_pass_holder_.password.data(), single_pass_holder_.password.size()},
                      maybe_open_key_stream(single_pass_holder_.keyfile.getValue()).get())
                  .SerializeAsString();
        auto config_stream = OSService::get_default().open_file_stream(
            single_pass_holder_.config_path.getValue().empty()
                ? absl::StrCat(single_pass_holder_.data_dir.getValue(), "/", kConfigFileName)
                : single_pass_holder_.config_path.getValue(),
            O_WRONLY | O_EXCL | O_CREAT,
            0644);
        config_stream->write(encrypted_data.data(), 0, encrypted_data.size());
        return 0;
    }

    const char* long_name() const noexcept override { return "create"; }

    char short_name() const noexcept override { return 'c'; }

    const char* help_message() const noexcept override { return "Create a new filesystem"; }
};

class ChangePasswordCommand : public CommandBase
{
private:
    CryptoPP::AlignedSecByteBlock old_password, new_password;

    DataDirHolder data_dir_holder_{cmdline()};

    TCLAP::ValueArg<std::string> old_key_file{
        "", "oldkeyfile", "Path to original key file", false, "", "path", cmdline()};
    TCLAP::ValueArg<std::string> new_key_file{
        "", "newkeyfile", "Path to new key file", false, "", "path", cmdline()};
    TCLAP::SwitchArg askoldpass{
        "",
        "askoldpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        cmdline(),
        false};
    TCLAP::SwitchArg asknewpass{
        "",
        "asknewpass",
        "When set to true, ask for password even if a key file is used. "
        "password+keyfile provides even stronger security than one of them alone.",
        cmdline(),
        false};
    TCLAP::ValueArg<std::string> oldpass{
        "",
        "oldpass",
        "The old password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "string",
        cmdline()};
    TCLAP::ValueArg<std::string> newpass{
        "",
        "newpass",
        "The new password (prefer manually typing or piping since those methods are more secure)",
        false,
        "",
        "string",
        cmdline()};
    Argon2idArgsHolder argon2{cmdline()};

    static void assign(std::string_view value, CryptoPP::AlignedSecByteBlock& output)
    {
        output.Assign(reinterpret_cast<const byte*>(value.data()), value.size());
    }

public:
    void parse_cmdline(int argc, const char* const* argv) override
    {
        CommandBase::parse_cmdline(argc, argv);

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
        auto original_path = data_dir_holder_.get_real_config_path_for_reading();
        byte buffer[16];
        generate_random(buffer, array_length(buffer));
        auto tmp_path = original_path + hexify(buffer, array_length(buffer));
        auto stream = OSService::get_default().open_file_stream(original_path, O_RDONLY, 0644);
        auto params = decrypt(
            OSService::get_default().open_file_stream(original_path, O_RDONLY, 0644)->as_string(),
            {old_password.data(), old_password.size()},
            maybe_open_key_stream(old_key_file).get());
        auto encrypted_data = encrypt(params,
                                      argon2.to_params(),
                                      {new_password.data(), new_password.size()},
                                      maybe_open_key_stream(new_key_file).get())
                                  .SerializeAsString();
        stream = OSService::get_default().open_file_stream(
            tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        DEFER(if (has_uncaught_exceptions()) {
            OSService::get_default().remove_file_nothrow(tmp_path);
        });
        stream->write(encrypted_data.data(), 0, encrypted_data.size());
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

class MountCommand : public CommandBase
{

public:
    MountCommand(std::string executable_name)
        : CommandBase(), executable_name_(std::move(executable_name))
    {
    }

public:
private:
#ifdef __linux__
    static constexpr inline long kKnownFileSystemTypesWithStableInodes[] = {
        0x9123683E,    // BTRFS
        0x2011BAB0,    // EXFAT
        0x137D,        // EXT
        0xEF53,        // EXT 2/3/4
        0xEF51,        // EXT 2 old
        0x4244,        // HFS
        0x482B,        // HFS+
        0x4858,        // HFSX
        0x5346544E,    // NTFS
        0x01021994,    // TMPFS
        0x58465342,    // XFS
        0x2FC12FC1,    // ZFS
    };
#endif

    SinglePasswordHolder single_pass_holder_{cmdline()};

    TCLAP::SwitchArg single_threaded{"s", "single", "Single threaded mode", cmdline()};
    TCLAP::SwitchArg background{
        "b",
        "background",
        "Spawn a child process to mount in the background (also available on Windows)",
        cmdline()};
    TCLAP::SwitchArg insecure{
        "i", "insecure", "Disable all integrity verification (insecure mode)", cmdline()};
    TCLAP::SwitchArg noxattr{"x", "noxattr", "Disable built-in xattr support", cmdline()};
    TCLAP::SwitchArg verbose{"v", "verbose", "Logs more verbose messages", cmdline()};
    TCLAP::SwitchArg trace{
        "", "trace", "Trace all calls into `securefs` (implies --verbose)", cmdline()};
    TCLAP::ValueArg<std::string> log{"",
                                     "log",
                                     "Path of the log file (may contain sensitive information)",
                                     false,
                                     "",
                                     "path",
                                     cmdline()};
    TCLAP::MultiArg<std::string> fuse_options{
        "o",
        "opt",
        "Additional FUSE options; this may crash the filesystem; use only for testing!",
        false,
        "options",
        cmdline()};
    TCLAP::UnlabeledValueArg<std::string> mount_point{
        "mount_point", "Mount point", true, "", "mount_point", cmdline()};
    TCLAP::ValueArg<std::string> fsname{
        "", "fsname", "Filesystem name shown when mounted", false, "securefs", "fsname", cmdline()};
    TCLAP::ValueArg<std::string> fssubtype{"",
                                           "fssubtype",
                                           "Filesystem subtype shown when mounted",
                                           false,
                                           "securefs",
                                           "fssubtype",
                                           cmdline()};
    TCLAP::SwitchArg noflock{"",
                             "noflock",
                             "Disables the usage of file locking. Needed on some network "
                             "filesystems. May cause data loss, so use it at your own risk!",
                             cmdline()};
    TCLAP::ValueArg<std::string> use_ino{
        "",
        "use-ino",
        "Asking libfuse to use the inode number reported by securefs as is. This may be needed if "
        "the application reads inode number. For full format, this should always be on. For lite "
        "format, the user needs to manually turn this on when the underlying filesystem has stable "
        "inode numbers (e.g. ext4, APFS, ZFS).",
        false,
        "auto",
        "auto/true/false",
        cmdline()};
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
                                               "",
                                               cmdline()};
    TCLAP::ValueArg<int> attr_timeout{"",
                                      "attr-timeout",
                                      "Number of seconds to cache file attributes. Default is 30.",
                                      false,
                                      30,
                                      "int",
                                      cmdline()};
    TCLAP::SwitchArg skip_dot_dot{
        "", "skip-dot-dot", "A no-op option retained for backwards compatibility", cmdline()};
    TCLAP::SwitchArg plain_text_names{"",
                                      "plain-text-names",
                                      "When enabled, securefs does not encrypt or decrypt file "
                                      "names. Use it at your own risk. No effect on full format.",
                                      cmdline()};
    TCLAP::ValueArg<int> uid_override{
        "",
        "uid-override",
        "Forces every file to be owned by this uid in the virtual filesystem. If the value is -1, "
        "then no override is in place",
        false,
        -1,
        "int",
        cmdline()};
    TCLAP::ValueArg<int> gid_override{
        "",
        "gid-override",
        "Forces every file to be owned by this gid in the virtual filesystem. If the value is -1, "
        "then no override is in place",
        false,
        -1,
        "int",
        cmdline()};
    TCLAP::SwitchArg allow_sensitive_logging{
        "", "allow-sensitive-logging", "Allow sensitive information in logs", cmdline()};
    TCLAP::ValueArg<int64_t> max_idle_seconds{
        "",
        "max-idle-seconds",
        "Maximum idle time before the filesystem is "
        "unmounted automatically. Default is 0 (no auto unmount).",
        false,
        0,
        "int64",
        cmdline()};
    DecryptedSecurefsParams fsparams{};

private:
    std::string executable_name_;

private:
#ifdef _WIN32
    static bool is_letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
    static bool is_drive_mount(std::string_view mount_point)
    {
        return mount_point.size() == 2 && is_letter(mount_point[0]) && mount_point[1] == ':';
    }
    static bool is_network_mount(std::string_view mount_point)
    {
        return absl::StartsWith(mount_point, "\\\\") && !absl::StartsWith(mount_point, "\\\\?\\");
    }
#endif

    bool should_use_ino()
    {
        if (use_ino.getValue() == "true")
        {
            return true;
        }
        else if (use_ino.getValue() == "false")
        {
            return false;
        }
        else if (use_ino.getValue() == "auto")
        {
            if (fsparams.has_full_format_params())
                return true;
#ifdef __linux__
            struct statfs st;
            if (statfs(single_pass_holder_.data_dir.getValue().c_str(), &st) < 0)
            {
                THROW_POSIX_EXCEPTION(errno, "statfs call failed");
            }
            return std::find(std::begin(kKnownFileSystemTypesWithStableInodes),
                             std::end(kKnownFileSystemTypesWithStableInodes),
                             st.f_type)
                != std::end(kKnownFileSystemTypesWithStableInodes);
#else
            return false;
#endif
        }
        throw_runtime_error("Invalid --use_ino. Must be true/false/auto.");
    }

private:
    InternalMountData build_internal_mount_data()
    {
        InternalMountData internal_mount_data;
        if (background.getValue())
        {
            internal_mount_data
                .mutable_background_logging();    // Ensure this message is not empty.
            if (global_logger)
            {
                internal_mount_data.mutable_background_logging()->set_logger_handle(
                    global_logger->get_native_handle());
            }
            if (verbose.getValue())
            {
                internal_mount_data.mutable_background_logging()->set_log_level(
                    InternalMountData::kLogVerbose);
            }
            if (trace.getValue())
            {
                internal_mount_data.mutable_background_logging()->set_log_level(
                    InternalMountData::kLogTrace);
            }
        }
        if (single_pass_holder_.data_dir.getValue() == mount_point.getValue())
        {
            WARN_LOG("Mounting a directory on itself may cause securefs to hang");
        }

#ifdef _WIN32
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
        std::string config_content;
        try
        {
            config_content
                = OSService::get_default()
                      .open_file_stream(
                          single_pass_holder_.get_real_config_path_for_reading(), O_RDONLY, 0)
                      ->as_string();
        }
        catch (const ExceptionBase& e)
        {
            if (e.error_number() == ENOENT)
            {
                ERROR_LOG("Encounter exception %s", e.what());
                ERROR_LOG(
                    "Config file %s does not exist. Perhaps you forget to run `create` command "
                    "first?",
                    single_pass_holder_.get_real_config_path_for_reading());
                throw;
            }
            throw;
        }
        *internal_mount_data.mutable_decrypted_params()
            = decrypt(config_content,
                      {single_pass_holder_.password.data(), single_pass_holder_.password.size()},
                      maybe_open_key_stream(single_pass_holder_.keyfile.getValue()).get());
        CryptoPP::SecureWipeBuffer(single_pass_holder_.password.data(),
                                   single_pass_holder_.password.size());

        // Populate mount_options from TCL Args
        {
            auto* mount_options = internal_mount_data.mutable_mount_options();
            // read_only is always false for now (see tReadOnly provider)
            mount_options->set_read_only(false);
            mount_options->set_disable_verification(insecure.getValue());
            if (uid_override.getValue() != -1)
                mount_options->set_uid_override(uid_override.getValue());
            if (gid_override.getValue() != -1)
                mount_options->set_gid_override(gid_override.getValue());
            // enable_xattr logic matches tEnableXattr provider
            bool enable_xattr = true;
            if (is_windows() || noxattr.getValue())
            {
                enable_xattr = false;
            }
            else
            {
                auto rc = OSService::get_default().listxattr(
                    single_pass_holder_.data_dir.getValue().c_str(), nullptr, 0);
                if (rc < 0)
                    enable_xattr = false;
            }
            mount_options->set_enable_xattr(enable_xattr);
            // case_fold and unicode_normalize_nfc from normalization arg
            if (plain_text_names.getValue())
            {
                mount_options->set_plain_text_names(true);
            }
            else
            {
                mount_options->set_plain_text_names(false);
                if (normalization.getValue() == "casefold"
                    || normalization.getValue() == "casefold+nfc")
                    mount_options->set_case_fold(true);
                if (normalization.getValue() == "nfc" || normalization.getValue() == "casefold+nfc")
                    mount_options->set_unicode_normalize_nfc(true);
            }
            mount_options->set_allow_sensitive_logging(allow_sensitive_logging.getValue());
            mount_options->set_max_idle_seconds(max_idle_seconds.getValue());
        }

        std::vector<std::string> fuse_args{
            executable_name_,
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
                absl::StrFormat("ThreadCount=%d", std::thread::hardware_concurrency()));
#endif
        }
        // Handling `daemon` ourselves, as FUSE's version interferes with our initialization.
        fuse_args.emplace_back("-f");

        if (should_use_ino())
        {
            fuse_args.emplace_back("-o");
            fuse_args.emplace_back("use_ino");
        }

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

#ifdef _WIN32
        if (!network_mount)
#endif
            fuse_args.emplace_back(mount_point.getValue());
        internal_mount_data.mutable_fuse_args()->Assign(fuse_args.begin(), fuse_args.end());
        internal_mount_data.set_data_dir(single_pass_holder_.data_dir.getValue());
        return internal_mount_data;
    }

    void parse_cmdline(int argc, const char* const* argv) override
    {
        CommandBase::parse_cmdline(argc, argv);

        single_pass_holder_.get_password(false);

        if (global_logger && verbose.getValue())
            global_logger->set_level(LoggingLevel::kLogVerbose);
        if (global_logger && trace.getValue())
            global_logger->set_level(LoggingLevel::kLogTrace);

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
        if (global_logger && verbose.getValue())
            global_logger->set_level(LoggingLevel::kLogVerbose);
        if (global_logger && trace.getValue())
            global_logger->set_level(LoggingLevel::kLogTrace);
    }

    int execute() override
    {
        recreate_logger();
        InternalMountData internal_mount_data = build_internal_mount_data();
        if (!background.getValue())
            return internal_mount(internal_mount_data);

        std::array<std::string_view, 2> args = {executable_name_, "protomount"};
        auto child = OSService::execute_child_process_with_data(
            args, internal_mount_data.SerializeAsString());
        while (true)
        {
            if (is_mounted_by_fuse(mount_point.getValue()))
            {
                return 0;
            }
            auto exit_code = child->exit_code();
            if (exit_code.has_value())
            {
                ERROR_LOG("Child process for mounting unexpectedly exited with code %d",
                          *exit_code);
                return *exit_code ? *exit_code : -1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    const char* long_name() const noexcept override { return "mount"; }

    char short_name() const noexcept override { return 'm'; }

    const char* help_message() const noexcept override { return "Mount an existing filesystem"; }

    lite_format::NameNormalizationFlags get_name_normalization_flags() const
    {
        lite_format::NameNormalizationFlags flags{};
        if (plain_text_names.getValue())
        {
            flags.no_op = true;
        }
        else if (normalization.getValue() == "nfc")
        {
            flags.should_normalize_nfc = true;
        }
        else if (normalization.getValue() == "casefold")
        {
            flags.should_case_fold = true;
        }
        else if (normalization.getValue() == "casefold+nfc")
        {
            flags.should_normalize_nfc = true;
            flags.should_case_fold = true;
        }
        else if (normalization.getValue() != "none")
        {
            throw_runtime_error("Invalid flag of --normalization: " + normalization.getValue());
        }
        flags.long_name_threshold = fsparams.lite_format_params().long_name_threshold();
        return flags;
    }
};

class VersionCommand : public CommandBase
{
public:
    int execute() override
    {
        using namespace CryptoPP;
        absl::PrintF("securefs %s\n", GIT_VERSION);
        absl::PrintF("Crypto++ %g\n", CRYPTOPP_VERSION / 100.0);
#ifdef _WIN32
        uint32_t vn;
        auto status = ::FspVersion(&vn);
        if (NT_SUCCESS(status))
            absl::PrintF("WinFsp %u.%u\n", vn >> 16, vn & 0xFFFFu);
        else
            absl::FPrintF(stderr, "Failed to query WinFsp version (code 0x%x)", status);
#else
        absl::PrintF("libfuse %d\n", ::fuse_version());
#endif

#ifdef CRYPTOPP_DISABLE_ASM
        fputs("\nBuilt without hardware acceleration\n", stdout);
#else
#if CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64
        absl::PrintF("\nHardware features available:\nSSE2: %v\nSSE3: %v\nSSE4.1: %v\nSSE4.2: "
                     "%v\nAVX: %v\nAVX2: %v\nAES-NI: %v\nCLMUL: %v\nSHA: %v\n",
                     CryptoPP::HasSSE2(),
                     CryptoPP::HasSSSE3(),
                     CryptoPP::HasSSE41(),
                     CryptoPP::HasSSE42(),
                     CryptoPP::HasAVX(),
                     CryptoPP::HasAVX2(),
                     CryptoPP::HasAESNI(),
                     CryptoPP::HasCLMUL(),
                     CryptoPP::HasSHA());
#elif CRYPTOPP_BOOL_ARM32 || CRYPTOPP_BOOL_ARMV8
        absl::PrintF(
            "\nHardware features available:\nNEON: %v\nAES: %v\nPMULL: %v\nSHA2: %v\nSHA3: %v\n",
            CryptoPP::HasNEON(),
            CryptoPP::HasAES(),
            CryptoPP::HasPMULL(),
            CryptoPP::HasSHA2(),
            CryptoPP::HasSHA3());
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
    SinglePasswordHolder single_pass_holder_{cmdline()};
    TCLAP::SwitchArg unmask{
        "", "unmask", "Disables the masking of master keys in the output", cmdline()};

public:
    const char* long_name() const noexcept override { return "info"; }

    char short_name() const noexcept override { return 'i'; }

    const char* help_message() const noexcept override
    {
        return "Display information about the filesystem in the JSON format";
    }

    void parse_cmdline(int argc, const char* const* argv) override
    {
        CommandBase::parse_cmdline(argc, argv);
        single_pass_holder_.get_password(false);
    }

    int execute() override
    {
        auto real_config_path = single_pass_holder_.get_real_config_path_for_reading();
        auto params = decrypt(
            OSService::get_default().open_file_stream(real_config_path, O_RDONLY, 0)->as_string(),
            {single_pass_holder_.password.data(), single_pass_holder_.password.size()},
            maybe_open_key_stream(single_pass_holder_.keyfile.getValue()).get());
        if (!unmask.getValue())
        {
            if (params.has_lite_format_params())
            {
                params.mutable_lite_format_params()->mutable_content_key()->clear();
                params.mutable_lite_format_params()->mutable_name_key()->clear();
                params.mutable_lite_format_params()->mutable_padding_key()->clear();
                params.mutable_lite_format_params()->mutable_xattr_key()->clear();
            }
            if (params.has_full_format_params())
            {
                params.mutable_full_format_params()->mutable_master_key()->clear();
            }
        }
        std::string json;
        google::protobuf::util::JsonPrintOptions options{};
        options.preserve_proto_field_names = true;
        options.add_whitespace = true;
        set_has_always_print_fields_with_no_presence(options);
        auto status = google::protobuf::util::MessageToJsonString(params, &json, options);
        if (!status.ok())
        {
            throw_runtime_error("Failed to convert params to JSON: " + status.ToString());
        }
        absl::PrintF("%s\n", json);
        return 0;
    }

private:
    template <class PrintOption>
    static constexpr auto has_always_print_fields_with_no_presence(int)
        -> decltype(std::declval<PrintOption>().always_print_fields_with_no_presence, true)
    {
        return true;
    }
    template <class PrintOption>
    static constexpr auto has_always_print_fields_with_no_presence(...)
    {
        return false;
    }
    template <class PrintOption>
    static void set_has_always_print_fields_with_no_presence(PrintOption& opt)
    {
        // Compatibility helper between old and new protobuf library.
        if constexpr (has_always_print_fields_with_no_presence<PrintOption>(0))
        {
            opt.always_print_fields_with_no_presence = true;
        }
        else
        {
            opt.always_print_primitive_fields = true;
        }
    }
};

class MigrateLongNameCommand : public CommandBase
{
private:
    SinglePasswordHolder single_pass_holder_{cmdline()};
    Argon2idArgsHolder argon2{cmdline()};

    static constexpr size_t kDefaultLongNameThreshold = 128;

public:
    const char* long_name() const noexcept override { return "migrate-long-name"; }
    char short_name() const noexcept override { return 0; }
    const char* help_message() const noexcept override
    {
        return "Migrate a lite format repository without long name support.";
    }
    void parse_cmdline(int argc, const char* const* argv) override
    {
        CommandBase::parse_cmdline(argc, argv);
        single_pass_holder_.get_password(false);
    }

    int execute() override
    {
        auto real_config_path = single_pass_holder_.get_real_config_path_for_reading();
        auto params = decrypt(
            OSService::get_default().open_file_stream(real_config_path, O_RDONLY, 0)->as_string(),
            {single_pass_holder_.password.data(), single_pass_holder_.password.size()},
            maybe_open_key_stream(single_pass_holder_.keyfile.getValue()).get());
        if (!params.has_lite_format_params())
        {
            throw_runtime_error("This command is only available for lite format repositories.");
        }
        if (params.lite_format_params().long_name_threshold() > 0)
        {
            WARN_LOG("Already supports long name.");
            return 0;
        }
        size_t max_filename_length = 0;
        OSService::get_default().recursive_traverse(
            single_pass_holder_.data_dir.getValue(),
            [&](const std::string& dir, const std::string& name, int type)
            {
                if (type == S_IFLNK)
                {
                    throw_runtime_error("Cannot migrate when symbolic links are present.");
                }
                max_filename_length = std::max(max_filename_length, name.size());
            });
        size_t threshold;
        if (max_filename_length < (kDefaultLongNameThreshold + 16) * 8 / 5)
        {
            threshold = kDefaultLongNameThreshold;
        }
        else
        {
            threshold = max_filename_length * 5 / 8 - 16;
        }
        params.mutable_lite_format_params()->set_long_name_threshold(threshold);
        auto encrypted_data
            = encrypt(params,
                      argon2.to_params(),
                      {single_pass_holder_.password.data(), single_pass_holder_.password.size()},
                      maybe_open_key_stream(single_pass_holder_.keyfile.getValue()).get())
                  .SerializeAsString();
        auto tmp_path = absl::StrCat(real_config_path, ".tmp");
        auto stream = OSService::get_default().open_file_stream(
            tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        DEFER(if (has_uncaught_exceptions()) {
            OSService::get_default().remove_file_nothrow(tmp_path);
        });
        stream->write(encrypted_data.data(), 0, encrypted_data.size());
        stream.reset();
        OSService::get_default().rename(tmp_path, real_config_path);
        return 0;
    }
};

class ProtoMountCommand : public CommandBase
{
public:
    const char* long_name() const noexcept override { return "protomount"; }
    char short_name() const noexcept override { return 0; }
    const char* help_message() const noexcept override
    {
        return "Internal only command to mount by protobuf message";
    }
    bool is_hidden() const noexcept override { return true; }
    int execute() override
    {
        OSService::set_file_descriptor_in_binary_mode(0);
        InternalMountData internal_mount_data;
        if (!internal_mount_data.ParseFromFileDescriptor(0))
        {
            ERROR_LOG("Failed to parse internal_mount_data from STDIN");
            return -1;
        }
        return internal_mount(internal_mount_data);
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
    void add_command(CommandBase* c) { commands.push_back(c); }
    int execute() override
    {
        fputs("# securefs\n", stdout);
        fputs("The command strucuture is `securefs ${SUBCOMMAND} ${SUBOPTIONS}`.\nSee below for "
              "available subcommands and relevant options\n\n",
              stdout);
        for (auto c : commands)
        {
            if (c->is_hidden())
            {
                continue;
            }
            if (c->short_name())
                absl::PrintF("## %s (short name: %c)\n", c->long_name(), c->short_name());
            else
                absl::PrintF("## %s\n", c->long_name());
            absl::PrintF("%s\n\n", c->help_message());
            auto&& cmdline = c->cmdline();

            std::vector<std::pair<size_t, TCLAP::Arg*>> prioritizedArgs;
            size_t index = 0;
            for (TCLAP::Arg* arg : cmdline.getArgList())
            {
                ++index;
                if (dynamic_cast<TCLAP::UnlabeledValueArg<std::string>*>(arg))
                {
                    prioritizedArgs.emplace_back(index, arg);
                }
                else
                {
                    prioritizedArgs.emplace_back(2 * cmdline.getArgList().size() - index, arg);
                }
            }
            std::sort(prioritizedArgs.begin(), prioritizedArgs.end());

            for (auto&& pair : prioritizedArgs)
            {
                TCLAP::Arg* arg = pair.second;
                if (auto a = dynamic_cast<TCLAP::UnlabeledValueArg<std::string>*>(arg); a)
                {
                    absl::PrintF(
                        "- **%s**: (*positional*) %s\n", a->getName(), a->getDescription());
                    continue;
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
                if (auto a = dynamic_cast<TCLAP::SwitchArg*>(arg); a)
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
                if (auto a = dynamic_cast<TCLAP::ValueArg<std::string>*>(arg); a)
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
                if (auto a = dynamic_cast<TCLAP::ValueArg<unsigned>*>(arg); a)
                {
                    absl::PrintF("*Default: %u.*\n", a->getValue());
                    continue;
                }
                if (auto a = dynamic_cast<TCLAP::ValueArg<int>*>(arg); a)
                {
                    absl::PrintF("*Default: %d.*\n", a->getValue());
                    continue;
                }
                if (auto a = dynamic_cast<TCLAP::ValueArg<int64_t>*>(arg); a)
                {
                    absl::PrintF("*Default: %d.*\n", a->getValue());
                    continue;
                }
                if (auto a = dynamic_cast<TCLAP::ValueArg<uint64_t>*>(arg); a)
                {
                    absl::PrintF("*Default: %d.*\n", a->getValue());
                    continue;
                }
                if (auto a = dynamic_cast<TCLAP::MultiArg<std::string>*>(arg); a)
                {
                    fputs("*This option can be specified multiple times.*\n", stdout);
                    continue;
                }
                throw_runtime_error(std::string("Unknown type of arg ") + typeid(*arg).name());
            }
        }
        return 0;
    }
};

class IsMountCommand : public CommandBase
{
private:
    TCLAP::UnlabeledValueArg<std::string> mount_point{
        "mount_point", "Mount point to check", true, "", "mount_point", cmdline()};

public:
    const char* long_name() const noexcept override { return "ismount"; }
    char short_name() const noexcept override { return 0; }
    const char* help_message() const noexcept override
    {
        return "Check if the given path is a securefs mount point";
    }

    int execute() override { return is_mounted_by_fuse(mount_point.getValue()) ? 0 : 1; }
};

class UnmountCommand : public CommandBase
{
private:
    TCLAP::UnlabeledValueArg<std::string> mount_point{
        "mount_point", "Mount point to unmount", true, "", "mount_point", cmdline()};

public:
    const char* long_name() const noexcept override { return "unmount"; }
    char short_name() const noexcept override { return 'u'; }
    const char* help_message() const noexcept override
    {
        return "Unmount the given securefs mount point";
    }

    int execute() override
    {
        trigger_unmount_by_fuse(mount_point.getValue());
        return 0;
    }
};

int commands_main(int argc, const char* const* argv)
{
    try
    {
        std::ios_base::sync_with_stdio(false);
        std::unique_ptr<CommandBase> cmds[] = {make_unique<MountCommand>(argv[0]),
                                               make_unique<CreateCommand>(),
                                               make_unique<ChangePasswordCommand>(),
                                               make_unique<VersionCommand>(),
                                               make_unique<InfoCommand>(),
                                               make_unique<MigrateLongNameCommand>(),
                                               make_unique<IsMountCommand>(),
                                               make_unique<UnmountCommand>(),
                                               make_unique<ProtoMountCommand>(),
                                               make_unique<DocCommand>()};

        const char* const program_name = argv[0];
        auto&& doc_command = dynamic_cast<DocCommand&>(*cmds[array_length(cmds) - 1]);
        for (auto&& c : cmds)
        {
            doc_command.add_command(c.get());
        }

        auto print_usage = [&]()
        {
            fputs("Available subcommands:\n\n", stderr);

            for (auto&& command : cmds)
            {
                if (command->is_hidden())
                {
                    continue;
                }
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
