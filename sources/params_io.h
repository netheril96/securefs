#pragma once

#include "params.pb.h"
#include "streams.h"

#include <exception>
#include <string_view>

namespace securefs
{
class PasswordOrKeyfileIncorrectException : public std::exception
{
public:
    const char* what() const noexcept override { return "Password/keyfile is incorrect"; }
};
DecryptedSecurefsParams decrypt(const LegacySecurefsJsonParams& legacy,
                                std::string_view password,
                                /* nullable */ StreamBase* key_stream);
DecryptedSecurefsParams decrypt(std::string_view content,
                                std::string_view password,
                                /* nullable */ StreamBase* key_stream);
}    // namespace securefs
