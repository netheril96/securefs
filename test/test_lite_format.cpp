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
#include <fruit/fruit.h>

#include <algorithm>
#include <array>
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

    fruit::Component<StreamOpener> get_test_component()
    {
        return fruit::createComponent()
            .registerProvider<fruit::Annotated<tContentMasterKey, key_type>()>(
                []() { return key_type(-1); })
            .registerProvider<fruit::Annotated<tPaddingMasterKey, key_type>()>(
                []() { return key_type(-2); })
            .registerProvider<fruit::Annotated<tSkipVerification, bool>()>([]() { return false; })
            .registerProvider<fruit::Annotated<tBlockSize, unsigned>()>([]() { return 64u; })
            .registerProvider<fruit::Annotated<tIvSize, unsigned>()>([]() { return 12u; })
            .registerProvider<fruit::Annotated<tMaxPaddingSize, unsigned>()>([]() { return 24u; });
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

    constexpr std::string_view kLongFileNameExample
        = "📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙"
          "📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙"
          "📙📙📙📙📙📙 "
          "📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙"
          "📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙"
          "📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙📙";

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
                .registerProvider<fruit::Annotated<tNameMasterKey, key_type>()>(
                    []() { return key_type(122); })
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
        }

        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", "..", "hello"});

        {
            fuse_file_info info{};
            REQUIRE(
                ops.vcreate(absl::StrCat("/", kLongFileNameExample).c_str(), 0644, &info, nullptr)
                == 0);
            REQUIRE(ops.vrelease(nullptr, &info, nullptr) == 0);
            CHECK(
                names(listdir(ops, "/"))
                == std::vector<std::string>{".", "..", "hello", std::string(kLongFileNameExample)});
        }

        {
            // Asserts read and write

            std::vector<char> written(333), read(444);
            generate_random(written.data(), written.size());
            fuse_file_info write_info{};
            write_info.flags = O_WRONLY;
            REQUIRE(ops.vopen(absl::StrCat("/", kLongFileNameExample).c_str(), &write_info, nullptr)
                    == 0);
            REQUIRE(ops.vwrite(nullptr, written.data(), written.size(), 1, &write_info, nullptr)
                    == written.size());

            std::thread concurrent_read_thread(
                [&]()
                {
                    fuse_file_info read_info{};
                    read_info.flags = O_RDONLY;
                    REQUIRE(ops.vopen(absl::StrCat("/", kLongFileNameExample).c_str(),
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
        CHECK(ops.vunlink(absl::StrCat("/", kLongFileNameExample).c_str(), nullptr) == 0);
        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", ".."});
        {
            LongNameLookupTable root_long_name_table(
                OSService::get_default().norm_path_narrowed(
                    absl::StrCat(temp_dir_name, "/", kLongNameTableFileName)),
                true);
            LockGuard<LongNameLookupTable> lg(root_long_name_table);
            CHECK(root_long_name_table.list_hashes() == std::vector<std::string>{});
        }
    }
}    // namespace
}    // namespace securefs::lite_format
