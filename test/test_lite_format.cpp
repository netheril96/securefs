#include "exceptions.h"
#include "lite_format.h"
#include "mystring.h"

#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_join.h>
#include <absl/strings/str_split.h>
#include <absl/strings/string_view.h>
#include <absl/utility/utility.h>
#include <array>
#include <cryptopp/sha.h>
#include <doctest/doctest.h>
#include <string>
#include <vector>

namespace securefs
{
namespace lite_format
{
    namespace
    {
        std::string hash(absl::string_view view)
        {
            CryptoPP::SHA256 sha;
            sha.Update(reinterpret_cast<const byte*>(view.data()), view.size());
            std::array<byte, 32> h;
            sha.TruncatedFinal(h.data(), h.size());
            return hexify(h);
        }
        class FakeNameTranslator : NameTranslator
        {
        public:
            std::string encrypt_full_path(absl::string_view path,
                                          std::string* out_encrypted_last_component) override
            {
                std::vector<absl::string_view> parts = absl::StrSplit(path, '/');
                std::vector<std::string> transformed;
                transformed.reserve(parts.size() + 2);

                for (absl::string_view p : parts)
                {
                    if (p.size() > 5)
                    {
                        transformed.emplace_back(absl::StrCat("hash-", hash(p)));
                    }
                    else
                    {
                        transformed.emplace_back(absl::StrCat("enc-", p));
                    }
                }
                if (out_encrypted_last_component != nullptr && parts.size() > 0
                    && parts.back().size() > 5)
                {
                    *out_encrypted_last_component = absl::StrCat("enc-", parts.back());
                }
                return absl::StrJoin(transformed, "/");
            }

            absl::variant<InvalidNameTag, LongNameTag, std::string>
            decrypt_path_component(absl::string_view path) override
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

            std::string encrypt_path_for_symlink(absl::string_view path) override
            {
                return absl::StrCat("/enc/", path);
            }
            std::string decrypt_path_from_symlink(absl::string_view path) override
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
    }    // namespace
}    // namespace lite_format
}    // namespace securefs
