#include "internal_mount.h"
#include "lite_format.h"
#include "mystring.h"
#include "myutils.h"
#include "params.pb.h"
#include "platform.h"
#include "tags.h"
#include "test_common.h"

#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_join.h>
#include <absl/strings/str_split.h>
#include <absl/utility/utility.h>
#include <cryptopp/sha.h>
#include <doctest/doctest.h>

#include <array>
#include <memory>
#include <string>
#include <string_view>

namespace securefs::lite_format
{
namespace
{
    std::string hash(std::string_view view)
    {
        CryptoPP::SHA256 sha;
        sha.Update(reinterpret_cast<const byte*>(view.data()), view.size());
        std::array<byte, 32> h;
        sha.TruncatedFinal(h.data(), h.size());
        return hexify(h);
    }

    TEST_CASE("component manipulation")
    {
        CHECK(NameTranslator::get_last_component("abcde") == "abcde");
        CHECK(NameTranslator::get_last_component("/abcde") == "abcde");
        CHECK(NameTranslator::get_last_component("/ccc/abcde") == "abcde");
        CHECK(NameTranslator::remove_last_component("abcde") == "");
        CHECK(NameTranslator::remove_last_component("/abcde") == "/");
        CHECK(NameTranslator::remove_last_component("/cc/abcde") == "/cc/");
    }

    TEST_CASE("legacy name translator")
    {
        auto flags = std::make_shared<NameNormalizationFlags>();

        auto t = make_name_translator(*flags, StrongType<key_type, tNameMasterKey>(key_type(-1)));
        CHECK(t->encrypt_full_path(u8"/abCDe/ß", nullptr)
              == "ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/AJRCK9GN87E3XDNGWKY48F6MEG752");
        CHECK(t->encrypt_full_path(u8"/abCDe/666", nullptr)
              == "ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/DX8MQEKK8ENI3UUE2J3Q76R5K9RS9JS");
        CHECK(t->encrypt_full_path(u8"/0/Be human readable and machine readable.", nullptr)
              == "KUPR9899P2FN4HH9A8X4WN3ZQQJS/"
                 "C5SRCFXE5DS89E45EP6YHSAWW54TRGCHUVKVX3N8YY7A7NE6M99TDDSPF6RN7ANRUYXKVRY9D8CP5GQKM"
                 "CZETWQC");
        CHECK(t->encrypt_path_for_symlink(u8"/abCDe/666")
              == "/ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/DX8MQEKK8ENI3UUE2J3Q76R5K9RS9JS");
    }

    TEST_CASE("new style name translator")
    {
        auto flags = std::make_shared<NameNormalizationFlags>();
        flags->long_name_suffix = ".long";
        flags->long_name_threshold = 10;

        auto t = make_name_translator(*flags, StrongType<key_type, tNameMasterKey>(key_type(-1)));
        CHECK(t->encrypt_full_path(u8"/abCDe/ß", nullptr)
              == ".//ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/AJRCK9GN87E3XDNGWKY48F6MEG752");
        CHECK(t->encrypt_full_path(u8"/abCDe/666", nullptr)
              == ".//ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/DX8MQEKK8ENI3UUE2J3Q76R5K9RS9JS");
        CHECK(t->encrypt_full_path(u8"/0/Be human readable and machine readable.", nullptr)
              == ".//KUPR9899P2FN4HH9A8X4WN3ZQQJS/"
                 "NRWRI3BSC9FBSNIXYIA8KGS64Z5DRA9DDVSCKBX7XENZVHKV94RIVEIYR6ZIN6MFHGUZXC9S8BWVI."
                 "long");
        CHECK(t->encrypt_path_for_symlink(
                  u8"/ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/DX8MQEKK8ENI3UUE2J3Q76R5K9RS9JS")
              == "/Z7P9D6ZA9ZYDP6M98RURCWEGNYRXSHF3YBU5WSZ9IH2MR8G6QFI2FCM4MTDSW7ACSTAX7M6RI3YPU5G7"
                 "JBKZDUHXSAPPKMD9/BH7XFEXQSHHCXX2WHTE7EDB23KJ5E84W6DD8W");
    }

    TEST_CASE("case folding name translator")
    {
        auto case_fold_flags = std::make_shared<NameNormalizationFlags>();
        case_fold_flags->should_case_fold = true;

        auto t = make_name_translator(*case_fold_flags,
                                      StrongType<key_type, tNameMasterKey>(key_type(-1)));
        CHECK(t->encrypt_full_path(u8"/abCDe/ß", nullptr)
              == t->encrypt_full_path(u8"/ABCde/ss", nullptr));
    }

    TEST_CASE("Unicode normalizing name translator")
    {
        auto normalize_nfc_flags = std::make_shared<NameNormalizationFlags>();
        normalize_nfc_flags->should_normalize_nfc = true;
        auto t = make_name_translator(*normalize_nfc_flags,
                                      StrongType<key_type, tNameMasterKey>(key_type(-1)));
        CHECK(t->encrypt_full_path("/aaa/\xc3\x84\xc3\x84\xc3\x84", nullptr)
              == t->encrypt_full_path("/aaa/A\xcc\x88"
                                      "A\xcc\x88"
                                      "\xc3\x84",
                                      nullptr));
    }

    TEST_CASE("Lite FuseHighLevelOps")
    {
        auto temp_dir_name = OSService::temp_name("tmp/lite", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);

        DecryptedSecurefsParams params;
        params.mutable_size_params()->set_block_size(4096);
        params.mutable_size_params()->set_iv_size(16);
        params.mutable_size_params()->set_max_padding_size(0);
        params.mutable_lite_format_params()->set_content_key("12345678901234567890123456789012");
        params.mutable_lite_format_params()->set_padding_key("12345678901234567890123456789012");
        params.mutable_lite_format_params()->set_name_key("12345678901234567890123456789012");
        params.mutable_lite_format_params()->set_xattr_key("12345678901234567890123456789012");
        params.mutable_lite_format_params()->set_long_name_threshold(9);

        MountOptions mount_options;
        mount_options.set_enable_xattr(true);
        testing::test_fuse_ops(*make_lite_format_fuse_high_level_ops(root, params, mount_options),
                               *root);
    }
}    // namespace
}    // namespace securefs::lite_format
