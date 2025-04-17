#include "xattr_name.h"

#include <absl/strings/escaping.h>
#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_split.h>

namespace securefs::generic_xattr
{
std::string encrypt_xattr_name(AES_SIV& aes_siv, std::string_view name)
{
    std::vector<char> buffer(name.size() + AES_SIV::IV_SIZE);
    aes_siv.encrypt_and_authenticate(
        name.data(), name.size(), nullptr, 0, buffer.data() + AES_SIV::IV_SIZE, buffer.data());
    return absl::StrCat("user.", absl::WebSafeBase64Escape({buffer.data(), buffer.size()}));
}
std::optional<std::string> decrypt_xattr_name(AES_SIV& aes_siv, std::string_view name)
{
    if (!absl::StartsWith(name, "user."))
    {
        return std::nullopt;
    }
    std::string decoded_buffer;
    if (!absl::WebSafeBase64Unescape(name.substr(5), &decoded_buffer))
    {
        return std::nullopt;
    }
    if (decoded_buffer.size() <= AES_SIV::IV_SIZE)
    {
        return std::nullopt;
    }
    std::string result(decoded_buffer.size() - AES_SIV::IV_SIZE, '\0');
    bool success = aes_siv.decrypt_and_verify(decoded_buffer.data() + AES_SIV::IV_SIZE,
                                              result.size(),
                                              nullptr,
                                              0,
                                              result.data(),
                                              decoded_buffer.data());
    if (success)
    {
        return result;
    }
    return std::nullopt;
}
int wrapped_listxattr(absl::FunctionRef<int(char*, size_t)> underlying_listxattr,
                      AES_SIV& aes_siv,
                      char* buffer,
                      size_t size)
{
    int rc = underlying_listxattr(nullptr, 0);
    if (rc <= 0)
    {
        return rc;
    }
    std::vector<char> encrypted_name_buffer(static_cast<size_t>(rc), 0);
    rc = underlying_listxattr(encrypted_name_buffer.data(), encrypted_name_buffer.size());
    if (rc <= 0)
    {
        return rc;
    }
    encrypted_name_buffer.resize(static_cast<size_t>(rc));
    std::vector<std::string> decrypted_names;

    for (std::string_view name : absl::StrSplit(
             std::string_view(encrypted_name_buffer.data(), encrypted_name_buffer.size()), '\0'))
    {
        auto decrypted_name = decrypt_xattr_name(aes_siv, name);
        if (!decrypted_name)
            continue;
        decrypted_names.emplace_back(std::move(*decrypted_name));
    }

    auto total_buffer_size = std::accumulate(decrypted_names.begin(),
                                             decrypted_names.end(),
                                             static_cast<size_t>(0),
                                             [](size_t sum, const std::string& name)
                                             { return sum + static_cast<int>(name.size()) + 1; });
    if (size == 0 || buffer == nullptr)
    {
        return static_cast<int>(total_buffer_size);
    }
    if (size < total_buffer_size)
    {
        return -ERANGE;
    }
    std::memset(buffer, 0, size);
    for (const auto& name : decrypted_names)
    {
        size_t name_size = name.size();
        if (name_size > size)
        {
            return -ERANGE;
        }
        std::memcpy(buffer, name.data(), name_size);
        buffer += name_size + 1;
        size -= name_size + 1;
    }
    return static_cast<int>(total_buffer_size);
}
}    // namespace securefs::generic_xattr
