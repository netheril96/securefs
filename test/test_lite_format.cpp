#include "crypto.h"
#include "fuse_high_level_ops_base.h"
#include "lite_format.h"
#include "lite_long_name_lookup_table.h"
#include "lock_guard.h"
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

#include <algorithm>
#include <array>
#include <fruit/injector.h>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

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

    fruit::Component<StreamOpener, fruit::Annotated<tNameMasterKey, key_type>> get_test_component()
    {
        return fruit::createComponent()
            .registerProvider<fruit::Annotated<tContentMasterKey, key_type>()>(
                []() { return key_type(100); })
            .registerProvider<fruit::Annotated<tPaddingMasterKey, key_type>()>(
                []() { return key_type(111); })
            .registerProvider<fruit::Annotated<tNameMasterKey, key_type>()>(
                []() { return key_type(122); })
            .registerProvider<fruit::Annotated<tSkipVerification, bool>()>([]() { return false; })
            .registerProvider<fruit::Annotated<tBlockSize, unsigned>()>([]() { return 64u; })
            .registerProvider<fruit::Annotated<tIvSize, unsigned>()>([]() { return 12u; })
            .registerProvider<fruit::Annotated<tMaxPaddingSize, unsigned>()>([]() { return 24u; });
    }

    TEST_CASE("case folding name translator")
    {
        auto flags = std::make_shared<NameNormalizationFlags>();
        flags->should_case_fold = true;
        fruit::Injector<NameTranslator> injector(
            +[](std::shared_ptr<NameNormalizationFlags> flags) -> fruit::Component<NameTranslator>
            {
                return fruit::createComponent()
                    .install(get_name_translator_component, flags)
                    .install(get_test_component);
            },
            std::move(flags));
        auto t = injector.get<NameTranslator*>();
        CHECK(t->encrypt_full_path("/abCDe/ß", nullptr)
              == t->encrypt_full_path("/ABCde/ss", nullptr));
    }

    TEST_CASE("Unicode normalizing name translator")
    {
        auto flags = std::make_shared<NameNormalizationFlags>();
        flags->should_normalize_nfc = true;
        fruit::Injector<NameTranslator> injector(
            +[](std::shared_ptr<NameNormalizationFlags> flags) -> fruit::Component<NameTranslator>
            {
                return fruit::createComponent()
                    .install(get_name_translator_component, flags)
                    .install(get_test_component);
            },
            std::move(flags));
        auto t = injector.get<NameTranslator*>();
        CHECK(t->encrypt_full_path("/aaa/ÄÄÄ", nullptr)
              == t->encrypt_full_path("/aaa/A\u0308A\u0308Ä", nullptr));
    }

    using ListDirResult = std::vector<std::pair<std::string, fuse_stat>>;
    ListDirResult listdir(FuseHighLevelOpsBase& op, const char* path)
    {
        ListDirResult result;
        fuse_file_info info{};
        REQUIRE(op.vopendir(path, &info, nullptr) == 0);
        DEFER(op.vreleasedir(path, &info, nullptr));
        REQUIRE(op.vreaddir(
                    path,
                    &result,
                    [](void* buf, const char* name, const fuse_stat* st, fuse_off_t off)
                    {
                        static_cast<ListDirResult*>(buf)->emplace_back(name,
                                                                       st ? *st : fuse_stat{});
                        return 0;
                    },
                    0,
                    &info,
                    nullptr)
                == 0);
        std::sort(result.begin(),
                  result.end(),
                  [](const auto& p1, const auto& p2) { return p1.first < p2.first; });
        return result;
    }
    std::vector<std::string> names(const ListDirResult& l)
    {
        std::vector<std::string> result;
        std::transform(l.begin(),
                       l.end(),
                       std::back_inserter(result),
                       [](const auto& pair) { return pair.first; });
        return result;
    }

    constexpr std::string_view kLongFileNameExample1
        = "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"
          "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"
          "✅✅✅✅✅✅ "
          "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"
          "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"
          "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"
          "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅";

    constexpr std::string_view kLongFileNameExample2
        = "🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️"
          "🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️";

    TEST_CASE("Lite FuseHighLevelOps")
    {
        auto whole_component
            = [](std::shared_ptr<OSService> os) -> fruit::Component<FuseHighLevelOps>
        {
            auto flags = std::make_shared<NameNormalizationFlags>();
            flags->supports_long_name = true;
            return fruit::createComponent()
                .install(get_name_translator_component, flags)
                .install(get_test_component)

                .bindInstance(*os);
        };

        auto temp_dir_name = OSService::temp_name("tmp/lite", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);

        fruit::Injector<FuseHighLevelOps> injector(+whole_component, root);
        auto& ops = injector.get<FuseHighLevelOps&>();
        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", ".."});

        {
            fuse_file_info info{};
            REQUIRE(ops.vcreate("/hello", 0644, &info, nullptr) == 0);
            REQUIRE(ops.vrelease(nullptr, &info, nullptr) == 0);

            fuse_stat st{};
            REQUIRE(ops.vgetattr("/hello", &st, nullptr) == 0);
            CHECK((st.st_mode & S_IFMT) == S_IFREG);
            CHECK(st.st_size == 0);
        }

        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", "..", "hello"});

        {
            fuse_file_info info{};
            REQUIRE(
                ops.vcreate(absl::StrCat("/", kLongFileNameExample1).c_str(), 0644, &info, nullptr)
                == 0);
            REQUIRE(ops.vrelease(nullptr, &info, nullptr) == 0);
            CHECK(names(listdir(ops, "/"))
                  == std::vector<std::string>{
                      ".", "..", "hello", std::string(kLongFileNameExample1)});
        }

        {
            // Asserts read and write

            std::vector<char> written(333), read(444);
            generate_random(written.data(), written.size());
            fuse_file_info write_info{};
            write_info.flags = O_WRONLY;
            REQUIRE(
                ops.vopen(absl::StrCat("/", kLongFileNameExample1).c_str(), &write_info, nullptr)
                == 0);
            REQUIRE(ops.vwrite(nullptr, written.data(), written.size(), 1, &write_info, nullptr)
                    == written.size());

            fuse_stat st{};
            CHECK(ops.vfgetattr(nullptr, &st, &write_info, nullptr) == 0);
            CHECK(st.st_size == written.size() + 1);

            std::thread concurrent_read_thread(
                [&]()
                {
                    fuse_file_info read_info{};
                    read_info.flags = O_RDONLY;
                    REQUIRE(ops.vopen(absl::StrCat("/", kLongFileNameExample1).c_str(),
                                      &read_info,
                                      nullptr)
                            == 0);
                    REQUIRE(ops.vread(nullptr, read.data(), read.size(), 0, &read_info, nullptr)
                            == written.size() + 1);
                    REQUIRE(ops.vrelease(nullptr, &read_info, nullptr) == 0);
                    CHECK(read.front() == 0);
                    CHECK(std::string_view(written.data(), written.size())
                          == std::string_view(read.data() + 1, written.size()));
                });
            concurrent_read_thread.join();

            REQUIRE(ops.vrelease(nullptr, &write_info, nullptr) == 0);
        }

        CHECK(ops.vunlink("/hello", nullptr) == 0);
        CHECK(ops.vunlink(absl::StrCat("/", kLongFileNameExample1).c_str(), nullptr) == 0);
        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", ".."});
        {
            LongNameLookupTable root_long_name_table(
                OSService::get_default().norm_path_narrowed(
                    absl::StrCat(temp_dir_name, "/", kLongNameTableFileName)),
                true);
            LockGuard<LongNameLookupTable> lg(root_long_name_table);
            CHECK(root_long_name_table.list_hashes() == std::vector<std::string>{});
        }

        REQUIRE(ops.vmkdir("/cbd", 0755, nullptr) == 0);
        REQUIRE(ops.vmkdir("/abc", 0755, nullptr) == 0);
        REQUIRE(ops.vrename("/abc", absl::StrCat("/cbd/", kLongFileNameExample2).c_str(), nullptr)
                == 0);
        {
            fuse_stat st{};
            REQUIRE(ops.vgetattr("/abc", &st, nullptr) == -ENOENT);
            REQUIRE(ops.vgetattr(absl::StrCat("/cbd/", kLongFileNameExample2).c_str(), &st, nullptr)
                    == 0);
            CHECK((st.st_mode & S_IFMT) == S_IFDIR);
            CHECK(names(listdir(ops, "/cbd"))
                  == std::vector<std::string>{".", "..", std::string(kLongFileNameExample2)});
        }
        {
            REQUIRE(ops.vrename(absl::StrCat("/cbd/", kLongFileNameExample2).c_str(),
                                absl::StrCat("/cbd/", kLongFileNameExample1).c_str(),
                                nullptr)
                    == 0);
            CHECK(names(listdir(ops, "/cbd"))
                  == std::vector<std::string>{".", "..", std::string(kLongFileNameExample1)});
        }
        {
            REQUIRE(
                ops.vrename(absl::StrCat("/cbd/", kLongFileNameExample1).c_str(), "/000", nullptr)
                == 0);
            REQUIRE(
                ops.vrename("/000", absl::StrCat("/cbd/", kLongFileNameExample1).c_str(), nullptr)
                == 0);
        }

        if (!is_windows())
        {
            auto symlink_location = absl::StrCat("/cbd/", kLongFileNameExample2, "sym");
            constexpr const char* symlink_target
                = "/888888888888888888888888888888/9999999999999999999/66666666666666666";
            REQUIRE(ops.vsymlink(symlink_target, symlink_location.c_str(), nullptr) == 0);

            fuse_stat st{};
            REQUIRE(ops.vgetattr(symlink_location.c_str(), &st, nullptr) == 0);
            CHECK((st.st_mode & S_IFMT) == S_IFLNK);
            CHECK(st.st_size == strlen(symlink_target));

            std::string read_symlink_target(st.st_size, '\0');
            REQUIRE(ops.vreadlink(symlink_location.c_str(),
                                  read_symlink_target.data(),
                                  read_symlink_target.size() + 1,
                                  nullptr)
                    == 0);
            CHECK(read_symlink_target == symlink_target);
        }

        if (!is_windows())
        {
            auto link_target = absl::StrCat("/cbd/", kLongFileNameExample2, kLongFileNameExample1);
            fuse_file_info info{};
            REQUIRE(ops.vcreate(link_target.c_str(), 0644, &info, nullptr) == 0);
            REQUIRE(ops.vlink(link_target.c_str(), "/check-mark", nullptr) == 0);
            fuse_stat st{};
            REQUIRE(ops.vfgetattr(nullptr, &st, &info, nullptr) == 0);
            CHECK(st.st_nlink == 2);
            CHECK(ops.vrelease(nullptr, &info, nullptr) == 0);
            CHECK(ops.vunlink(link_target.c_str(), nullptr) == 0);
            REQUIRE(ops.vgetattr("/check-mark", &st, nullptr) == 0);
            CHECK(st.st_nlink == 1);
        }
    }
}    // namespace
}    // namespace securefs::lite_format
