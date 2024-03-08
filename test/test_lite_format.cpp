#include "fuse_high_level_ops_base.h"
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
#include <fruit/fruit.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
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
    class FakeNameTranslator : public NameTranslator
    {
    public:
        INJECT(FakeNameTranslator()) {}
        static constexpr size_t kMaxNameLength = 144;
        std::string encrypt_full_path(std::string_view path,
                                      std::string* out_encrypted_last_component) override
        {
            std::vector<std::string_view> parts = absl::StrSplit(path, '/');
            std::vector<std::string> transformed;
            transformed.reserve(parts.size() + 2);
            transformed.emplace_back(".");

            for (std::string_view p : parts)
            {
                if (p.empty())
                {
                    transformed.emplace_back();
                    continue;
                }
                if (p.size() > kMaxNameLength)
                {
                    transformed.emplace_back(absl::StrCat("hash-", hash(p)));
                }
                else
                {
                    transformed.emplace_back(absl::StrCat("enc-", p));
                }
            }
            if (out_encrypted_last_component != nullptr && parts.size() > 0
                && parts.back().size() > kMaxNameLength)
            {
                *out_encrypted_last_component = absl::StrCat("enc-", parts.back());
            }
            return absl::StrJoin(transformed, "/");
        }

        std::variant<InvalidNameTag, LongNameTag, std::string>
        decrypt_path_component(std::string_view path) override
        {
            if (absl::StartsWithIgnoreCase(path, "enc-"))
            {
                auto sub = path.substr(4);
                return std::string(sub);
            }
            if (absl::StartsWithIgnoreCase(path, "hash-"))
            {
                return LongNameTag{};
            }
            return InvalidNameTag{};
        }

        std::string encrypt_path_for_symlink(std::string_view path) override
        {
            return absl::StrCat("/enc/", path);
        }
        std::string decrypt_path_from_symlink(std::string_view path) override
        {
            return std::string(path.substr(5));
        }

        unsigned max_virtual_path_component_size(unsigned physical_path_component_size) override
        {
            return 1024;
        }
    };

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
            .registerProvider<fruit::Annotated<tMaxPaddingSize, unsigned>()>([]() { return 24u; })

            ;
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
            return fruit::createComponent()
                .bind<NameTranslator, FakeNameTranslator>()
                .install(get_test_component)
                .bindInstance(*os);
        };

        auto temp_dir_name = OSService::temp_name("tmp/lite", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);

        fruit::Injector<FuseHighLevelOps> injector(+whole_component, root);
        auto& ops = injector.get<FuseHighLevelOps&>();
        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", ".."});

        fuse_file_info info{};
        REQUIRE(ops.vcreate("/hello", 0644, &info, nullptr) == 0);
        REQUIRE(ops.vrelease(nullptr, &info, nullptr) == 0);

        CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", "..", "hello"});

        REQUIRE(ops.vcreate(absl::StrCat("/", kLongFileNameExample).c_str(), 0644, &info, nullptr)
                == 0);
        REQUIRE(ops.vrelease(nullptr, &info, nullptr) == 0);
        CHECK(names(listdir(ops, "/"))
              == std::vector<std::string>{".", "..", "hello", std::string(kLongFileNameExample)});
    }
}    // namespace
}    // namespace securefs::lite_format
