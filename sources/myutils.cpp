#include "myutils.h"
#include "exceptions.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <cctype>
#include <string.h>
#include <system_error>
#include <time.h>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace securefs
{

std::string to_lower(const std::string& str)
{
    std::string result = str;
    for (char& c : result)
    {
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    }
    return result;
}

std::string sane_strerror(int error_number) { return std::system_category().message(error_number); }

void parse_hex(const std::string& hex, byte* output, size_t len)
{
    if (hex.size() % 2 != 0)
        throw InvalidArgumentException("Hex string must have an even length");
    if (hex.size() / 2 != len)
        throw InvalidArgumentException("Mismatch hex and raw length");

    for (size_t i = 0; i < hex.size(); i += 2, ++output)
    {
        switch (hex[i])
        {
        case '0':
            *output = 0x0;
            break;
        case '1':
            *output = 0x10;
            break;
        case '2':
            *output = 0x20;
            break;
        case '3':
            *output = 0x30;
            break;
        case '4':
            *output = 0x40;
            break;
        case '5':
            *output = 0x50;
            break;
        case '6':
            *output = 0x60;
            break;
        case '7':
            *output = 0x70;
            break;
        case '8':
            *output = 0x80;
            break;
        case '9':
            *output = 0x90;
            break;
        case 'a':
            *output = 0xa0;
            break;
        case 'b':
            *output = 0xb0;
            break;
        case 'c':
            *output = 0xc0;
            break;
        case 'd':
            *output = 0xd0;
            break;
        case 'e':
            *output = 0xe0;
            break;
        case 'f':
            *output = 0xf0;
            break;
        default:
            throw InvalidArgumentException("Invalid character in hexadecimal string");
        }
        switch (hex[i + 1])
        {
        case '0':
            *output += 0x0;
            break;
        case '1':
            *output += 0x1;
            break;
        case '2':
            *output += 0x2;
            break;
        case '3':
            *output += 0x3;
            break;
        case '4':
            *output += 0x4;
            break;
        case '5':
            *output += 0x5;
            break;
        case '6':
            *output += 0x6;
            break;
        case '7':
            *output += 0x7;
            break;
        case '8':
            *output += 0x8;
            break;
        case '9':
            *output += 0x9;
            break;
        case 'a':
            *output += 0xa;
            break;
        case 'b':
            *output += 0xb;
            break;
        case 'c':
            *output += 0xc;
            break;
        case 'd':
            *output += 0xd;
            break;
        case 'e':
            *output += 0xe;
            break;
        case 'f':
            *output += 0xf;
            break;
        default:
            throw InvalidArgumentException("Invalid character in hexadecimal string");
        }
    }
}
#ifndef HAS_THREAD_LOCAL

#include <pthread.h>

template <class T>
class ThreadLocalStorage
{
private:
    pthread_key_t m_pkey;

public:
    explicit ThreadLocalStorage()
    {
        int rc = pthread_key_create(&m_pkey, [](void* ptr) { delete static_cast<T*>(ptr); });
        if (rc < 0)
            throw std::runtime_error("Fail to initialize pthread TLS");
    }

    ~ThreadLocalStorage() { pthread_key_delete(m_pkey); }

    T* get()
    {
        auto ptr = pthread_getspecific(m_pkey);
        if (!ptr)
        {
            ptr = new T();

            int rc = pthread_setspecific(m_pkey, ptr);
            if (rc < 0)
                throw std::runtime_error("Fail to set TLS value");
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
    static ThreadLocalStorage<CryptoPP::AutoSeededRandomPool> pool;
    pool->GenerateBlock(static_cast<byte*>(data), size);
#else
    thread_local CryptoPP::AutoSeededRandomPool pool;
    pool.GenerateBlock(static_cast<byte*>(data), size);
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
        throw InvalidArgumentException("Output length too large");
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
        NULL_EXCEPT();

    if (prompt)
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    size_t actual_read = 0;
    auto output = static_cast<unsigned char*>(password);

    while (actual_read < max_length)
    {
        int ch = fgetc(fp);
        if (ch == EOF)
        {
            if (feof(fp))
                break;
            if (ferror(fp))
                throw OSException(errno);
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
#ifndef _WIN32
    if (!fp || !password)
        NULL_EXCEPT();

    int fd = fileno(fp);
    struct termios old_termios, new_termios;
    int rc = ::tcgetattr(fd, &old_termios);
    if (rc < 0)
        throw OSException(errno);
    if (!(old_termios.c_lflag & ECHO))
        throw InvalidArgumentException("Unechoed terminal");

    memcpy(&new_termios, &old_termios, sizeof(old_termios));
    new_termios.c_lflag &= ~ECHO;
    new_termios.c_lflag |= ECHONL;
    rc = ::tcsetattr(fd, TCSAFLUSH, &new_termios);
    if (rc < 0)
        throw OSException(errno);
    auto retval = insecure_read_password(fp, prompt, password, max_length);
    (void)::tcsetattr(fd, TCSAFLUSH, &old_termios);
    return retval;
#else
    return insecure_read_password(fp, prompt, password, max_length);
#endif
}

std::vector<std::string> split(const char* str, size_t length, char separator)
{
    const char* end = str + length;
    const char* start = str;
    std::vector<std::string> result;

    while (str < end)
    {
        if (*str == separator)
        {
            if (start < str)
                result.emplace_back(start, str);
            start = str + 1;
        }
        ++str;
    }

    if (start < end)
        result.emplace_back(start, end);
    return result;
}

#ifndef _WIN32
static void find_ids_helper(const std::string& current_dir,
                            std::unordered_set<id_type, id_hash>& result)
{
    struct DirGuard
    {
        DIR* dp = nullptr;

        DirGuard() {}
        ~DirGuard() { ::closedir(dp); }
    };

    DIR* dp = ::opendir(current_dir.c_str());
    if (!dp)
    {
        if (errno == ENOTDIR)
            return;
        throw POSIXException(errno, fmt::format("Opening dir {}", current_dir));
    }

    DirGuard guard;
    guard.dp = dp;
    id_type id;
    std::string hex(id_type::size() * 2, 0);

    while (true)
    {
        errno = 0;
        dirent* dr = ::readdir(dp);
        if (!dr && errno)
            throw POSIXException(errno, fmt::format("Reading dir {}", current_dir));
        if (!dr)
            break;
        std::string name(dr->d_name);
        if (name == "." || name == "..")
            continue;
        if (dr->d_type == DT_REG && ends_with(name.data(), name.size(), ".meta", strlen(".meta")))
        {
            std::string total_name
                = current_dir + '/' + name.substr(0, name.size() - strlen(".meta"));
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
                else if (namechar != '/')
                {
                    throw std::runtime_error(
                        fmt::format("File \"{}\" has extension .meta, but not a valid securefs "
                                    "meta filename. Please cleanup the underlying storage first.",
                                    total_name));
                }
                --j;
            }
            parse_hex(hex, id.data(), id.size());
            result.insert(id);
        }
        else if (dr->d_type == DT_DIR)
        {
            find_ids_helper(current_dir + '/' + name, result);
        }
    }
}

std::unordered_set<id_type, id_hash> find_all_ids(const std::string& basedir)
{
    std::unordered_set<id_type, id_hash> result;
    find_ids_helper(basedir, result);
    return result;
}
#endif

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len)
{
    return size >= suffix_len && memcmp(str + size - suffix_len, suffix, suffix_len) == 0;
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
