#pragma once

#include "myutils.h"
#include "params.pb.h"
#include "platform.h"
#include "streams.h"

#include <absl/types/span.h>

#include <exception>
#include <memory>
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
DecryptedSecurefsParams decrypt(const EncryptedSecurefsParams& encparams,
                                absl::Span<const byte> password,
                                /* nullable */ StreamBase* key_stream);
DecryptedSecurefsParams decrypt(std::string_view content,
                                absl::Span<const byte> password,
                                /* nullable */ StreamBase* key_stream);
EncryptedSecurefsParams encrypt(const DecryptedSecurefsParams& decparams,
                                const EncryptedSecurefsParams::Argon2idParams& argon2id_params,
                                absl::Span<const byte> password,
                                /* nullable */ StreamBase* key_stream);

inline std::shared_ptr<FileStream> maybe_open_key_stream(const std::string& keyfile)
{
    if (keyfile.empty())
    {
        return {};
    }
    return OSService::get_default().open_file_stream(keyfile, O_RDONLY, 0);
}
}    // namespace securefs
