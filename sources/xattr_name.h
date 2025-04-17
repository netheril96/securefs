#pragma once

#include "crypto.h"
#include "myutils.h"

#include <absl/functional/function_ref.h>

#include <optional>
#include <string>
#include <string_view>

// Handling extended attribute name encryption/decryption
// on platforms other than Apple.
namespace securefs::generic_xattr
{

std::string encrypt_xattr_name(AES_SIV& aes_siv, std::string_view name);
std::optional<std::string> decrypt_xattr_name(AES_SIV& aes_siv, std::string_view name);
int wrapped_listxattr(absl::FunctionRef<int(char*, size_t)> underlying_listxattr,
                      AES_SIV& aes_siv,
                      char* buffer,
                      size_t size);

}    // namespace securefs::generic_xattr
