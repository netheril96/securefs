#include "myutils.h"
#include "exceptions.h"
#include "platform.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <string.h>
#include <system_error>
#include <time.h>
#include <vector>

#ifndef WIN32
#include <termios.h>
#include <unistd.h>
#else
#include <conio.h>
#endif

namespace securefs
{
std::string errno_to_string() { return sane_strerror(errno); }

void hmac_sha256_calculate(
    const void* message, size_t msg_len, const void* key, size_t key_len, void* mac, size_t mac_len)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(static_cast<const byte*>(key), key_len);
    hmac.Update(static_cast<const byte*>(message), msg_len);
    hmac.TruncatedFinal(static_cast<byte*>(mac), mac_len);
}

bool hmac_sha256_verify(const void* message,
                        size_t msg_len,
                        const void* key,
                        size_t key_len,
                        const void* mac,
                        size_t mac_len)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(static_cast<const byte*>(key), key_len);
    hmac.Update(static_cast<const byte*>(message), msg_len);
    return hmac.TruncatedVerify(static_cast<const byte*>(mac), mac_len);
}

unsigned int pbkdf_hmac_sha256(const void* password,
                               size_t pass_len,
                               const void* salt,
                               size_t salt_len,
                               unsigned int min_iterations,
                               double min_seconds,
                               void* derived,
                               size_t derive_len)
{
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    return kdf.DeriveKey(static_cast<byte*>(derived),
                         derive_len,
                         0,
                         static_cast<const byte*>(password),
                         pass_len,
                         static_cast<const byte*>(salt),
                         salt_len,
                         min_iterations,
                         min_seconds);
}

static void hkdf_expand(const void* distilled_key,
                        size_t dis_len,
                        const void* info,
                        size_t info_len,
                        void* output,
                        size_t out_len)
{
    typedef CryptoPP::HMAC<CryptoPP::SHA256> hmac_type;
    if (out_len > 255 * hmac_type::DIGESTSIZE)
        throwInvalidArgumentException("Output length too large");
    hmac_type calculator(static_cast<const byte*>(distilled_key), dis_len);
    byte* out = static_cast<byte*>(output);
    size_t i = 0, j = 0;
    byte counter = 1;
    while (i + j < out_len)
    {
        calculator.Update(out + i, j);
        calculator.Update(static_cast<const byte*>(info), info_len);
        calculator.Update(&counter, sizeof(counter));
        ++counter;
        auto small_len = std::min<size_t>(out_len - i - j, hmac_type::DIGESTSIZE);
        calculator.TruncatedFinal(out + i + j, small_len);
        i += j;
        j = small_len;
    }
}

void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len)
{
    if (salt && salt_len)
    {
        byte distilled_key[32];
        hmac_sha256_calculate(key, key_len, salt, salt_len, distilled_key, sizeof(distilled_key));
        hkdf_expand(distilled_key, sizeof(distilled_key), info, info_len, output, out_len);
    }
    else
    {
        hkdf_expand(key, key_len, info, info_len, output, out_len);
    }
}

static void find_ids_helper(const std::string& current_dir,
                            std::unordered_set<id_type, id_hash>& result)
{
    id_type id;
    std::string hex(id_type::size() * 2, 0);
    OSService::recursive_traverse_callback callback
        = [&id, &result, &hex](StringRef dir, StringRef name) -> bool {
        if (name == "." || name == "..")
            return true;
        if (name.ends_with(".meta"))
        {
            std::string total_name = dir + "/" + name.substr(0, name.size() - strlen(".meta"));
            hex.assign(hex.size(), 0);
            ptrdiff_t i = hex.size() - 1, j = total_name.size() - 1;
            while (i >= 0 && j >= 0)
            {
                char namechar = total_name[j];
                if ((namechar >= '0' && namechar <= '9') || (namechar >= 'a' && namechar <= 'f'))
                {
                    hex[i] = namechar;
                    --i;
                }
                else if (namechar != '/' && namechar != '\\')
                {
                    throw_runtime_error(
                        strprintf("File \"%s\" has extension .meta, but not a valid securefs "
                                  "meta filename. Please cleanup the underlying storage first.",
                                  total_name.c_str()));
                }
                --j;
            }
            parse_hex(hex, id.data(), id.size());
            result.insert(id);
        }
        return true;
    };

    OSService::get_default().recursive_traverse(current_dir, callback);
}

std::unordered_set<id_type, id_hash> find_all_ids(const std::string& basedir)
{
    std::unordered_set<id_type, id_hash> result;
    find_ids_helper(basedir, result);
    return result;
}

std::string get_user_input_until_enter()
{
    std::string result;
    while (true)
    {
        int ch = getchar();
        if (ch == EOF)
        {
            return result;
        }
        if (ch == '\r' || ch == '\n')
        {
            while (!result.empty() && isspace(static_cast<unsigned char>(result.back())))
                result.pop_back();
            result.push_back('\n');
            return result;
        }
        else if (!result.empty() || !isspace(ch))
        {
            result.push_back(static_cast<unsigned char>(ch));
        }
    }
    return result;
}

void respond_to_user_action(
    const std::unordered_map<std::string, std::function<void(void)>>& actionMap)
{
    while (true)
    {
        std::string cmd = get_user_input_until_enter();
        if (cmd.empty() || cmd.back() != '\n')
        {
            // EOF
            return;
        }
        auto it = actionMap.find(cmd);
        if (it == actionMap.end())
        {
            puts("Invalid command");
            continue;
        }
        it->second();
        break;
    }
}
}
