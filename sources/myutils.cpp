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

#if !defined(HAS_THREAD_LOCAL) && !defined(WIN32)
template <class T>
class ThreadLocalStorage
{
private:
    pthread_key_t m_pkey;

public:
    explicit ThreadLocalStorage()
    {
        int rc = pthread_key_create(&m_pkey, [](void* ptr) { delete static_cast<T*>(ptr); });
        if (rc)
            THROW_POSIX_EXCEPTION(rc, "Fail to initialize pthread TLS");
    }

    ~ThreadLocalStorage() { pthread_key_delete(m_pkey); }

    T* get()
    {
        void* ptr = pthread_getspecific(m_pkey);
        if (!ptr)
        {
            ptr = new T();
            int rc = pthread_setspecific(m_pkey, ptr);
            if (rc)
                THROW_POSIX_EXCEPTION(rc, "Fail to set TLS value");
        }
        return static_cast<T*>(ptr);
    }

    T* operator->() { return get(); }
    T& operator*() { return *get(); }
};
#endif

void generate_random(void* data, size_t size)
{
#ifndef HAS_THREAD_LOCAL
    static ThreadLocalStorage<CryptoPP::AutoSeededRandomPool> rng;
    return rng->GenerateBlock(static_cast<byte*>(data), size);
#else
    thread_local CryptoPP::AutoSeededRandomPool rng;
    return rng.GenerateBlock(static_cast<byte*>(data), size);
#endif
}

void aes_gcm_encrypt(const void* plaintext,
                     size_t text_len,
                     const void* header,
                     size_t header_len,
                     const void* key,
                     size_t key_len,
                     const void* iv,
                     size_t iv_len,
                     void* mac,
                     size_t mac_len,
                     void* ciphertext)
{
#ifndef HAS_THREAD_LOCAL
    static ThreadLocalStorage<CryptoPP::GCM<CryptoPP::AES>::Encryption> tls_encryptor;
    static ThreadLocalStorage<std::vector<byte>> tls_last_key;
    // Avoid expensive table computation by SetKey()

    auto encryptor = tls_encryptor.get();
    auto last_key = tls_last_key.get();
#else
    thread_local CryptoPP::GCM<CryptoPP::AES>::Encryption tls_encryptor;
    thread_local std::vector<byte> tls_last_key;

    auto encryptor = &tls_encryptor;
    auto last_key = &tls_last_key;
#endif

    if (last_key->size() == key_len && memcmp(last_key->data(), key, key_len) == 0)
    {
        encryptor->Resynchronize(static_cast<const byte*>(iv), static_cast<int>(iv_len));
    }
    else
    {
        encryptor->SetKeyWithIV(
            static_cast<const byte*>(key), key_len, static_cast<const byte*>(iv), iv_len);
        last_key->assign(static_cast<const byte*>(key), static_cast<const byte*>(key) + key_len);
    }

    encryptor->SpecifyDataLengths(header_len, text_len);
    encryptor->Update(static_cast<const byte*>(header), header_len);
    encryptor->ProcessString(
        static_cast<byte*>(ciphertext), static_cast<const byte*>(plaintext), text_len);
    encryptor->TruncatedFinal(static_cast<byte*>(mac), mac_len);
}

bool aes_gcm_decrypt(const void* ciphertext,
                     size_t text_len,
                     const void* header,
                     size_t header_len,
                     const void* key,
                     size_t key_len,
                     const void* iv,
                     size_t iv_len,
                     const void* mac,
                     size_t mac_len,
                     void* plaintext)
{
#ifndef HAS_THREAD_LOCAL
    static ThreadLocalStorage<CryptoPP::GCM<CryptoPP::AES>::Decryption> tls_decryptor;
    static ThreadLocalStorage<std::vector<byte>> tls_last_key;
    // Avoid expensive table computation by SetKey()

    auto decryptor = tls_decryptor.get();
    auto last_key = tls_last_key.get();
#else
    thread_local CryptoPP::GCM<CryptoPP::AES>::Decryption tls_decryptor;
    thread_local std::vector<byte> tls_last_key;

    auto decryptor = &tls_decryptor;
    auto last_key = &tls_last_key;
#endif

    if (last_key->size() == key_len && memcmp(last_key->data(), key, key_len) == 0)
    {
        decryptor->Resynchronize(static_cast<const byte*>(iv), static_cast<int>(iv_len));
    }
    else
    {
        decryptor->SetKeyWithIV(
            static_cast<const byte*>(key), key_len, static_cast<const byte*>(iv), iv_len);
        last_key->assign(static_cast<const byte*>(key), static_cast<const byte*>(key) + key_len);
    }

    decryptor->SpecifyDataLengths(header_len, text_len);
    decryptor->Update(static_cast<const byte*>(header), header_len);
    decryptor->ProcessString(
        static_cast<byte*>(plaintext), static_cast<const byte*>(ciphertext), text_len);
    return decryptor->TruncatedVerify(static_cast<const byte*>(mac), mac_len);
}

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

size_t insecure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length)
{
    if (!fp || !password)
        throwVFSException(EFAULT);

    if (prompt)
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    size_t actual_read = 0;
    auto output = static_cast<unsigned char*>(password);

    while (actual_read < max_length)
    {
        int ch = getc(fp);
        if (ch == EOF)
        {
            if (feof(fp))
                break;
            if (ferror(fp))
                THROW_POSIX_EXCEPTION(errno, "getc");
        }
        if (ch == '\0' || ch == '\n' || ch == '\r')
            break;
        *output = static_cast<unsigned char>(ch);
        ++output;
        ++actual_read;
    }

    if (actual_read >= max_length)
        fprintf(stderr,
                "Warning: password is longer than %llu and therefore truncated\n",
                static_cast<unsigned long long>(max_length));
    return actual_read;
}

size_t secure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length)
{
#ifdef WIN32
    if (!fp || !password)
        throwVFSException(EFAULT);

    if (fp != stdin)
        return insecure_read_password(fp, prompt, password, max_length);

    if (prompt)
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    size_t actual_read = 0;
    auto output = static_cast<unsigned char*>(password);

    while (actual_read < max_length)
    {
        int ch = _getch();
        if (ch == EOF)
        {
            if (feof(fp))
                break;
            if (ferror(fp))
                throwVFSException(errno);
        }
        if (ch == '\0' || ch == '\n' || ch == '\r')
            break;
        *output = static_cast<unsigned char>(ch);
        ++output;
        ++actual_read;
    }
    putc('\n', stdout);

    if (actual_read >= max_length)
        fprintf(stderr,
                "Warning: password is longer than %llu and therefore truncated\n",
                static_cast<unsigned long long>(max_length));
    return actual_read;
#else
    if (!fp || !password)
        throwVFSException(EFAULT);

    int fd = fileno(fp);
    struct termios old_termios, new_termios;
    int rc = ::tcgetattr(fd, &old_termios);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "tcgetattr");
    if (!(old_termios.c_lflag & ECHO))
        throwInvalidArgumentException("Unechoed terminal");

    memcpy(&new_termios, &old_termios, sizeof(old_termios));
    new_termios.c_lflag &= ~ECHO;
    new_termios.c_lflag |= ECHONL;
    rc = ::tcsetattr(fd, TCSAFLUSH, &new_termios);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "tcsetattr");
    auto retval = insecure_read_password(fp, prompt, password, max_length);
    (void)::tcsetattr(fd, TCSAFLUSH, &old_termios);
    return retval;
#endif
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
