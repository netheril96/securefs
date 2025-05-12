#include "fuse_hook.h"
#include "lite_format.h"
#include "mystring.h"
#include "myutils.h"
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
#include <fruit/component.h>
#include <fruit/fruit.h>
#include <fruit/injector.h>

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

    fruit::Component<StreamOpener,
                     XattrCryptor,
                     fruit::Annotated<tNameMasterKey, key_type>,
                     fruit::Annotated<tXattrMasterKey, key_type>,
                     fruit::Annotated<tEnableXattr, bool>,
                     fruit::Annotated<tAllowSensitiveLogging, bool>>
    get_test_component()
    {
        return fruit::createComponent()
            .registerProvider<fruit::Annotated<tContentMasterKey, key_type>()>(
                []() { return key_type(100); })
            .registerProvider<fruit::Annotated<tPaddingMasterKey, key_type>()>(
                []() { return key_type(111); })
            .registerProvider<fruit::Annotated<tNameMasterKey, key_type>()>(
                []() { return key_type(122); })
            .registerProvider<fruit::Annotated<tXattrMasterKey, key_type>()>(
                []() { return key_type(108); })
            .registerProvider<fruit::Annotated<tVerify, bool>()>([]() { return true; })
            .registerProvider<fruit::Annotated<tBlockSize, unsigned>()>([]() { return 64u; })
            .registerProvider<fruit::Annotated<tIvSize, unsigned>()>([]() { return 12u; })
            .registerProvider<fruit::Annotated<tMaxPaddingSize, unsigned>()>([]() { return 24u; })
            .registerProvider<fruit::Annotated<tEnableXattr, bool>()>([]() { return true; })
            .registerProvider<fruit::Annotated<tAllowSensitiveLogging, bool>()>([]()
                                                                                { return true; });
    }

    TEST_CASE("case folding name translator")
    {
        fruit::Injector<NameTranslator> injector(
            +[](std::shared_ptr<NameNormalizationFlags> name_normalization_flags)
                -> fruit::Component<NameTranslator>
            {
                return fruit::createComponent()
                    .install(get_name_translator_component, name_normalization_flags)
                    .install(get_test_component);
            },
            std::make_shared<NameNormalizationFlags>(
                NameNormalizationFlags{.should_case_fold = true}));
        auto t = injector.get<NameTranslator*>();
        CHECK(t->encrypt_full_path(u8"/abCDe/ß", nullptr)
              == t->encrypt_full_path(u8"/ABCde/ss", nullptr));
    }

    TEST_CASE("Unicode normalizing name translator")
    {
        fruit::Injector<NameTranslator> injector(
            +[](std::shared_ptr<NameNormalizationFlags> name_normalization_flags)
                -> fruit::Component<NameTranslator>
            {
                return fruit::createComponent()
                    .install(get_name_translator_component, name_normalization_flags)
                    .install(get_test_component);
            },
            std::make_shared<NameNormalizationFlags>(
                NameNormalizationFlags{.should_normalize_nfc = true}));
        auto t = injector.get<NameTranslator*>();

        CHECK(t->encrypt_full_path("/aaa/\xc3\x84\xc3\x84\xc3\x84", nullptr)
              == t->encrypt_full_path("/aaa/A\xcc\x88"
                                      "A\xcc\x88"
                                      "\xc3\x84",
                                      nullptr));
    }

    TEST_CASE("Lite FuseHighLevelOps")
    {
        auto whole_component = [](OSService* os) -> fruit::Component<FuseHighLevelOps>
        {
            auto flags = std::make_shared<NameNormalizationFlags>();
            flags->long_name_threshold = 133;
            return fruit::createComponent()
                .install(get_name_translator_component, flags)
                .install(get_test_component)
                .bindInstance(*os);
        };

        auto temp_dir_name = OSService::temp_name("tmp/lite", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        OSService root(temp_dir_name);

        fruit::Injector<FuseHighLevelOps> injector(+whole_component, &root);
        auto& ops = injector.get<FuseHighLevelOps&>();
        testing::test_fuse_ops(ops, root);
    }
}    // namespace
}    // namespace securefs::lite_format
