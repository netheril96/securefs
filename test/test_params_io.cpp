#include "mystring.h"
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

    TEST_CASE("Decrypt legacy config")
    {
        OSService root(refdir());
        auto differ = std::make_unique<google::protobuf::util::MessageDifferencer>();
        EncryptedSecurefsParams::Argon2idParams argon2id_params;
        argon2id_params.set_memory_cost(64);
        argon2id_params.set_parallelism(2);
        argon2id_params.set_time_cost(2);

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
                    try
                    {
                        params.emplace_back(
                            decrypt(content, as_byte_span(password), key_stream.get()));
                    }
                    catch (const PasswordOrKeyfileIncorrectException&)
                    {
                        CHECK_MESSAGE(
                            false,
                            absl::StrFormat(
                                "Decryption failed due to password/keyfile mismatch for file %s "
                                "(password %s, keyfile %v)",
                                root.norm_path_narrowed(absl::StrCat(dir_name, "/", name)),
                                password,
                                bool(key_stream)));
                    }
                    ++total_cases;

                    auto encparams = encrypt(
                        params.back(), argon2id_params, as_byte_span(password), key_stream.get());
                    auto decrypted_again
                        = decrypt(encparams, as_byte_span(password), key_stream.get());
                    CHECK(differ->Compare(decrypted_again, params.back()));

                    CHECK_THROWS(decrypt(content, as_byte_span("ABC"), key_stream.get()));
                }

                REQUIRE(params.size() > 1);
                for (size_t i = 1; i < params.size(); ++i)
                {
                    REQUIRE(differ->Compare(params[i - 1], params[i]));
                }
            }
        }

        REQUIRE(total_cases == 15 * 4 * 2);
    }
}    // namespace
}    // namespace securefs
