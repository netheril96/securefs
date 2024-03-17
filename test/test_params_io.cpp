#include "params.pb.h"
#include "params_io.h"
#include "platform.h"
#include "streams.h"
#include "tags.h"

#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <doctest/doctest.h>
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/util/message_differencer.h>

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace securefs
{
namespace
{
    std::string refdir()
    {
        const char* dir = std::getenv("SECUREFS_TEST_REFERENCE");
        REQUIRE(dir != nullptr);
        return dir;
    }

    TEST_CASE("Decrypte legacy config")
    {
        OSService root(refdir());
        google::protobuf::util::MessageDifferencer differ;

        unsigned total_cases = 0;
        for (int version = 1; version <= 4; ++version)
        {
            for (bool padding : {false, true})
            {
                auto dir_name
                    = padding ? absl::StrFormat("%d-padded", version) : absl::StrCat(version);
                auto traverser = root.create_traverser(dir_name);

                std::vector<DecryptedSecurefsParams> params;

                fuse_stat st{};
                std::string name;

                while (traverser->next(&name, &st))
                {
                    if (!absl::StartsWith(name, ".securefs") || !absl::EndsWith(name, ".json"))
                    {
                        continue;
                    }
                    std::string password;
                    std::shared_ptr<StreamBase> key_stream;
                    if (absl::StrContainsIgnoreCase(name, "PASSWORD"))
                    {
                        password = "abc";
                    }
                    if (absl::StrContainsIgnoreCase(name, "KEYFILE"))
                    {
                        key_stream = root.open_file_stream("keyfile", O_RDONLY, 0);
                    }
                    if (password.empty())
                    {
                        password = " ";
                    }
                    auto content
                        = root.open_file_stream(absl::StrCat(dir_name, "/", name), O_RDONLY, 0)
                              ->as_string();
                    auto decrypted = decrypt(content, password, key_stream.get());
                    ++total_cases;
                    params.emplace_back(std::move(decrypted));

                    CHECK_THROWS(decrypt(content, "ABC", key_stream.get()));
                }

                REQUIRE(params.size() > 1);
                for (size_t i = 0; i < params.size(); ++i)
                {
                    REQUIRE(differ.Compare(params[i - 1], params[i]));
                }
            }
        }

        REQUIRE(total_cases == 15 * 4 * 2);
    }
}    // namespace
}    // namespace securefs
