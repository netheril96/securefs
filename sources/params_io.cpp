#include "params_io.h"

#include "exceptions.h"
#include "mystring.h"
#include "myutils.h"
#include "params.pb.h"
#include "streams.h"

#include <absl/functional/function_ref.h>
#include <absl/strings/escaping.h>
#include <absl/strings/str_format.h>
#include <absl/types/span.h>
#include <argon2.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/sha.h>

#include <cstdint>
#include <google/protobuf/util/json_util.h>
#include <string>
#include <string_view>
#include <vector>

namespace securefs
{
namespace
{
    const char* const PBKDF_ALGO_PKCS5 = "pkcs5-pbkdf2-hmac-sha256";
    const char* const PBKDF_ALGO_SCRYPT = "scrypt";
    const char* const PBKDF_ALGO_ARGON2ID = "argon2id";

    absl::Span<const byte> as_byte_span(std::string_view view)
    {
        return {reinterpret_cast<const byte*>(view.data()), view.size()};
    }

    key_type compute_password_derived_key(const LegacySecurefsJsonParams& legacy,
                                          std::string_view password,
                                          absl::Span<const byte> effective_salt)
    {
        key_type result;
        if (legacy.pbkdf() == PBKDF_ALGO_ARGON2ID)
        {
            int rc = ::argon2id_hash_raw(legacy.iterations(),
                                         legacy.argon2_m_cost(),
                                         legacy.argon2_p(),
                                         password.data(),
                                         password.size(),
                                         effective_salt.data(),
                                         effective_salt.size(),
                                         result.data(),
                                         result.size());
            if (rc != 0)
            {
                throw_runtime_error(absl::StrFormat("Argon2id hash failure: %d", rc));
            }
        }
        else if (legacy.pbkdf() == PBKDF_ALGO_SCRYPT)
        {
            CryptoPP::Scrypt scrypt;
            scrypt.DeriveKey(result.data(),
                             result.size(),
                             reinterpret_cast<const byte*>(password.data()),
                             password.size(),
                             effective_salt.data(),
                             effective_salt.size(),
                             legacy.iterations(),
                             legacy.scrypt_r(),
                             legacy.scrypt_p());
        }
        else if (legacy.pbkdf() == PBKDF_ALGO_PKCS5 || legacy.pbkdf().empty())
        {
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
            kdf.DeriveKey(result.data(),
                          result.size(),
                          0,
                          reinterpret_cast<const byte*>(password.data()),
                          password.size(),
                          effective_salt.data(),
                          effective_salt.size(),
                          legacy.iterations());
        }
        else
        {
            throw_runtime_error(absl::StrFormat("Unknown pbkdf algorithm %s", legacy.pbkdf()));
        }
        return result;
    }

    key_type hmac_sha256(absl::Span<const byte> base_key, StreamBase& key_stream)
    {
        key_type result;
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(base_key.data(), base_key.size());
        std::vector<byte> buffer(4096);
        for (offset_type off = 0;;)
        {
            auto sz = key_stream.read(buffer.data(), off, buffer.size());
            if (sz <= 0)
            {
                break;
            }
            hmac.Update(buffer.data(), sz);
            off += sz;
        }
        hmac.TruncatedFinal(result.data(), result.size());
        return result;
    }

    // Because we have had two historical ways of key derivation when key file is present, we need
    // to try them in sequence.
    bool try_password_derived_key(const LegacySecurefsJsonParams& legacy,
                                  std::string_view password,
                                  /* nullable */ StreamBase* key_stream,
                                  absl::FunctionRef<bool(const key_type&)> try_func)
    {
        auto original_salt = absl::HexStringToBytes(legacy.salt());

        if (key_stream == nullptr)
        {
            return try_func(compute_password_derived_key(
                legacy, password, as_byte_span(absl::HexStringToBytes(original_salt))));
        }
        return try_func(compute_password_derived_key(
                   legacy, password, hmac_sha256(as_byte_span(original_salt), *key_stream)))
            || try_func(hmac_sha256(
                compute_password_derived_key(legacy, password, as_byte_span(original_salt)),
                *key_stream));
    }

    std::string get_version_header(unsigned version)
    {
        switch (version)
        {
        case 1:
        case 2:
        case 3:
            return "version=1";    // These headers are all the same for backwards compatible
                                   // behavior with old mistakes
        case 4:
            return "version=4";
        default:
            throwInvalidArgumentException("Unknown format version");
        }
    }
    void assign(std::string* str, absl::Span<const byte> span)
    {
        str->assign(reinterpret_cast<const char*>(span.data()), span.size());
    }
}    // namespace
DecryptedSecurefsParams decrypt(const LegacySecurefsJsonParams& legacy,
                                std::string_view password,
                                /* nullable */ StreamBase* key_stream)
{

    DecryptedSecurefsParams result;
    result.mutable_size_params()->set_block_size(legacy.has_block_size() ? legacy.block_size()
                                                                         : 4096);
    result.mutable_size_params()->set_iv_size(legacy.has_iv_size() ? legacy.iv_size() : 32);
    result.mutable_size_params()->set_max_padding_size(legacy.max_padding());

    std::vector<byte> master_key;

    bool success = try_password_derived_key(
        legacy,
        password,
        key_stream,
        [&](const key_type& wrapping_key)
        {
            auto iv = absl::HexStringToBytes(legacy.encrypted_key().iv());
            auto mac = absl::HexStringToBytes(legacy.encrypted_key().mac());
            auto ciphertext = absl::HexStringToBytes(legacy.encrypted_key().ciphertext());
            auto header = get_version_header(legacy.version());

            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(
                wrapping_key.data(), wrapping_key.size(), as_byte_span(iv).data(), iv.size());
            master_key.resize(ciphertext.size());
            return dec.DecryptAndVerify(master_key.data(),
                                        as_byte_span(mac).data(),
                                        mac.size(),
                                        as_byte_span(iv).data(),
                                        static_cast<int>(iv.size()),
                                        as_byte_span(header).data(),
                                        header.size(),
                                        as_byte_span(ciphertext).data(),
                                        ciphertext.size());
        });

    if (!success)
    {
        throw_runtime_error("Password or keyfile combination is incorrect");
    }
    if (legacy.version() == 4)
    {
        if (master_key.size() != 3 * key_type::size() || master_key.size() != 4 * key_type::size())
        {
            throw_runtime_error("Invalid master key size");
        }
        assign(result.mutable_lite_format_params()->mutable_name_key(),
               {master_key.data(), key_type::size()});
        assign(result.mutable_lite_format_params()->mutable_content_key(),
               {master_key.data() + key_type::size(), key_type::size()});
        assign(result.mutable_lite_format_params()->mutable_xattr_key(),
               {master_key.data() + 2 * key_type::size(), key_type::size()});
        if (master_key.size() == 4 * key_type::size())
        {
            assign(result.mutable_lite_format_params()->mutable_padding_key(),
                   {master_key.data() + 3 * key_type::size(), key_type::size()});
        }
    }
    else
    {
        assign(result.mutable_full_format_params()->mutable_master_key(),
               {master_key.data(), master_key.size()});
    }
    if (legacy.version() == 1)
    {
        result.mutable_full_format_params()->set_legacy_file_table_io(true);
    }
    if (legacy.version() == 3)
    {
        result.mutable_full_format_params()->set_store_time(true);
    }
    if (result.has_lite_format_params() && legacy.long_name_component())
    {
        result.mutable_lite_format_params()->set_long_name_threshold(128);
    }
    if (result.has_lite_format_params())
    {
        warn_if_key_not_random(
            as_byte_span(result.lite_format_params().name_key()), __FILE__, __LINE__);
        warn_if_key_not_random(
            as_byte_span(result.lite_format_params().content_key()), __FILE__, __LINE__);
        warn_if_key_not_random(
            as_byte_span(result.lite_format_params().xattr_key()), __FILE__, __LINE__);
        if (!result.lite_format_params().padding_key().empty())
        {
            warn_if_key_not_random(
                as_byte_span(result.lite_format_params().padding_key()), __FILE__, __LINE__);
        }
    }
    else
    {
        warn_if_key_not_random(
            as_byte_span(result.full_format_params().master_key()), __FILE__, __LINE__);
    }
    return result;
}

DecryptedSecurefsParams decrypt(std::string_view content,
                                std::string_view password,
                                /* nullable */ StreamBase* key_stream)
{
    LegacySecurefsJsonParams legacy;
    auto status = google::protobuf::util::JsonStringToMessage(content, &legacy);
    if (!status.ok())
    {
        throw_runtime_error("Parse JSON config fails: " + status.ToString());
    }
    return decrypt(legacy, password, key_stream);
}
}    // namespace securefs
