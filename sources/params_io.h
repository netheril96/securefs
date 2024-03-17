#pragma once

#include "myutils.h"
#include "params.pb.h"
#include "streams.h"

#include <absl/types/span.h>

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
                                absl::Span<const byte> password,
                                /* nullable */ StreamBase* key_stream);
DecryptedSecurefsParams decrypt(std::string_view content,
                                absl::Span<const byte> password,
                                /* nullable */ StreamBase* key_stream);
}    // namespace securefs
