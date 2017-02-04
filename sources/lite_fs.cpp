#include "lite_fs.h"
#include "constants.h"
#include "logger.h"

#include <cryptopp/base32.h>

#include <cerrno>
#include <mutex>

namespace securefs
{
namespace lite
{
    File::File(std::shared_ptr<securefs::FileStream> file_stream,
               const key_type& master_key,
               unsigned block_size,
               unsigned iv_size,
               bool check)
        : m_file_stream(file_stream)
    {
        m_file_stream->lock(true);
        DEFER(m_file_stream->unlock());
        m_crypt_stream.emplace(file_stream, master_key, block_size, iv_size, check);
    }

    File::~File() {}

    void File::fstat(struct fuse_stat* stat)
    {
        m_file_stream->fstat(stat);
        stat->st_size = AESGCMCryptStream::calculate_real_size(
            stat->st_size, m_crypt_stream->get_block_size(), m_crypt_stream->get_iv_size());
    }

    FileSystem::FileSystem(std::shared_ptr<securefs::OSService> root,
                           const key_type& name_key,
                           const key_type& content_key,
                           const key_type& xattr_key,
                           unsigned block_size,
                           unsigned iv_size,
                           unsigned flags)
        : m_name_encryptor(name_key.data(), name_key.size())
        , m_content_key(content_key)
        , m_root(std::move(root))
        , m_block_size(block_size)
        , m_iv_size(iv_size)
        , m_flags(flags)
    {
        byte null_iv[12] = {0};
        m_xattr_enc.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        m_xattr_dec.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));

        global_logger->trace("Filesystem created at %p", this);
    }

    FileSystem::~FileSystem() { global_logger->trace("Filesystem destroyed at %p", this); }

    InvalidFilenameException::~InvalidFilenameException() {}
    std::string InvalidFilenameException::message() const
    {
        return strprintf("Invalid filename \"%s\"", m_filename.c_str());
    }

    std::string encrypt_path(CryptoPP::Base32Encoder& encoder, AES_SIV& encryptor, StringRef path)
    {
        byte buffer[2032];
        std::string result;
        result.reserve((path.size() * 8 + 4) / 5);
        size_t last_nonseparator_index = 0;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;
                    if (slice_size > 2000)
                        throwVFSException(ENAMETOOLONG);
                    encryptor.encrypt_and_authenticate(
                        slice, slice_size, nullptr, 0, buffer + AES_SIV::IV_SIZE, buffer);
                    encoder.Initialize();
                    encoder.Put(buffer, slice_size + AES_SIV::IV_SIZE);
                    encoder.MessageEnd();
                    auto encoded_size = encoder.MaxRetrievable();
                    if (encoded_size > 0)
                    {
                        auto current_size = result.size();
                        result.resize(current_size + encoded_size);
                        encoder.Get(reinterpret_cast<byte*>(&result[current_size]), encoded_size);
                    }
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    std::string encrypt_path(AES_SIV& encryptor, StringRef path)
    {
        CryptoPP::Base32Encoder enc;
        return encrypt_path(enc, encryptor, path);
    }

    std::string decrypt_path(AES_SIV& decryptor, StringRef path)
    {
        byte buffer[2032];
        byte string_buffer[2032];
        std::string result;
        result.reserve(path.size() * 5 / 8);
        size_t last_nonseparator_index = 0;
        CryptoPP::Base32Decoder decoder;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;

                    decoder.Initialize();
                    decoder.Put(reinterpret_cast<const byte*>(slice), slice_size);
                    decoder.MessageEnd();

                    auto decoded_size = decoder.MaxRetrievable();
                    if (decoded_size > sizeof(buffer))
                        throwVFSException(ENAMETOOLONG);
                    if (decoded_size <= AES_SIV::IV_SIZE)
                        throwVFSException(EINVAL);
                    decoder.Get(buffer, decoded_size);

                    bool success = decryptor.decrypt_and_verify(buffer + AES_SIV::IV_SIZE,
                                                                decoded_size - AES_SIV::IV_SIZE,
                                                                nullptr,
                                                                0,
                                                                string_buffer,
                                                                buffer);
                    if (!success)
                        throw InvalidFilenameException(path.to_string());
                    result.append(reinterpret_cast<const char*>(string_buffer),
                                  decoded_size - AES_SIV::IV_SIZE);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    std::string FileSystem::translate_path(StringRef path, bool preserve_leading_slash)
    {
        if (path.empty())
        {
            return {};
        }
        else if (path.size() == 1 && path[0] == '/')
        {
            if (preserve_leading_slash)
            {
                return "/";
            }
            else
            {
                return ".";
            }
        }
        else
        {
            std::string str = lite::encrypt_path(m_encoder, m_name_encryptor, path);
            if (!preserve_leading_slash && !str.empty() && str[0] == '/')
            {
                str.erase(str.begin());
            }
            global_logger->trace("Translate path %s into %s", path.c_str(), str.c_str());
            return str;
        }
    }

    AutoClosedFile FileSystem::open(StringRef path, int flags, fuse_mode_t mode)
    {
        if (flags & O_APPEND)
            throwVFSException(ENOTSUP);

        if ((flags & O_ACCMODE) == O_WRONLY)
        {
            flags = (flags & ~O_ACCMODE) | O_RDWR;
        }
        if ((flags & O_CREAT) && !(mode & 0400))
        {
            THROW_POSIX_EXCEPTION(
                EINVAL, "Creating a file without read access is not supported on this filesystem");
        }
        auto file_stream = m_root->open_file_stream(translate_path(path, false), flags, mode);
        AutoClosedFile fp(new File(file_stream,
                                   m_content_key,
                                   m_block_size,
                                   m_iv_size,
                                   (m_flags & kOptionNoAuthentication) == 0));
        if (flags & O_TRUNC)
            fp->resize(0);
        return fp;
    }

    bool FileSystem::stat(StringRef path, struct fuse_stat* buf)
    {
        auto enc_path = translate_path(path, false);
        if (!m_root->stat(enc_path, buf))
            return false;
        if (buf->st_size <= 0)
            return true;
        switch (buf->st_mode & S_IFMT)
        {
        case S_IFLNK:
        {
            std::string buffer(buf->st_size, '\0');
            if (m_root->readlink(enc_path, &buffer[0], buffer.size()) != buf->st_size)
                throwVFSException(EIO);
            auto resolved = decrypt_path(m_name_encryptor, buffer);
            buf->st_size = resolved.size();
            break;
        }
        case S_IFDIR:
            break;
        case S_IFREG:
            buf->st_size
                = AESGCMCryptStream::calculate_real_size(buf->st_size, m_block_size, m_iv_size);
            break;
        default:
            throwVFSException(ENOTSUP);
        }
        return true;
    }

    void FileSystem::mkdir(StringRef path, fuse_mode_t mode)
    {
        m_root->mkdir(translate_path(path, false), mode);
    }

    void FileSystem::rmdir(StringRef path)
    {
        m_root->remove_directory(translate_path(path, false));
    }

    void FileSystem::rename(StringRef from, StringRef to)
    {
        m_root->rename(translate_path(from, false), translate_path(to, false));
    }

    void FileSystem::chmod(StringRef path, fuse_mode_t mode)
    {
        if (!(mode & 0400))
        {
            global_logger->warn("Change the mode of file %s to 0%o which denies user write access. "
                                "Mysterious bugs will occur.",
                                path.c_str(),
                                static_cast<unsigned>(mode));
        }
        m_root->chmod(translate_path(path, false), mode);
    }

    size_t FileSystem::readlink(StringRef path, char* buf, size_t size)
    {
        if (size <= 0)
            return size;

        auto max_size = size / 5 * 8 + 32;
        auto underbuf = securefs::make_unique_array<char>(max_size);
        memset(underbuf.get(), 0, max_size);
        m_root->readlink(translate_path(path, false), underbuf.get(), max_size - 1);
        std::string resolved = decrypt_path(m_name_encryptor, underbuf.get());
        size_t copy_size = std::min(resolved.size(), size - 1);
        memcpy(buf, resolved.data(), copy_size);
        buf[copy_size] = '\0';
        return copy_size;
    }

    void FileSystem::symlink(StringRef to, StringRef from)
    {
        auto eto = translate_path(to, true), efrom = translate_path(from, false);
        m_root->symlink(eto, efrom);
    }

    void FileSystem::utimens(StringRef path, const fuse_timespec* ts)
    {
        m_root->utimens(translate_path(path, false), ts);
    }

    void FileSystem::unlink(StringRef path) { m_root->remove_file(translate_path(path, false)); }

    void FileSystem::link(StringRef src, StringRef dest)
    {
        m_root->link(translate_path(src, false), translate_path(dest, false));
    }

    void FileSystem::statvfs(struct fuse_statvfs* buf) { m_root->statfs(buf); }

    class LiteDirectoryTraverser : public DirectoryTraverser
    {
    private:
        CryptoPP::Base32Decoder decoder;
        std::unique_ptr<DirectoryTraverser> m_underlying_traverser;
        AES_SIV* m_name_encryptor;

    public:
        explicit LiteDirectoryTraverser(std::unique_ptr<DirectoryTraverser> underlying_traverser,
                                        AES_SIV* name_encryptor)
            : m_underlying_traverser(std::move(underlying_traverser))
            , m_name_encryptor(name_encryptor)
        {
        }
        ~LiteDirectoryTraverser() {}

        bool next(std::string* name, fuse_mode_t* type) override
        {
            std::string under_name;
            byte buffer[2000];

            while (1)
            {
                if (!m_underlying_traverser->next(&under_name, type))
                    return false;
                if (!name)
                    return true;

                if (under_name.empty() || under_name[0] == '.')
                    continue;

                try
                {
                    decoder.Initialize();
                    decoder.Put(reinterpret_cast<const byte*>(under_name.data()),
                                under_name.size());
                    decoder.MessageEnd();
                    auto size = decoder.MaxRetrievable();
                    if (size > sizeof(buffer) || size <= AES_SIV::IV_SIZE)
                    {
                        global_logger->warn("Skipping too large/small encrypted filename %s",
                                            under_name.c_str());
                        continue;
                    }

                    decoder.Get(buffer, sizeof(buffer));
                    name->assign(size - AES_SIV::IV_SIZE, '\0');
                    bool success = m_name_encryptor->decrypt_and_verify(buffer + AES_SIV::IV_SIZE,
                                                                        size - AES_SIV::IV_SIZE,
                                                                        nullptr,
                                                                        0,
                                                                        &(*name)[0],
                                                                        buffer);
                    if (!success)
                    {
                        global_logger->warn("Skipping filename %s in virtual directory that does "
                                            "not decode properly",
                                            under_name.c_str());
                        continue;
                    }
                }
                catch (const std::exception& e)
                {
                    global_logger->warn("Skipping filename %s due to exception in decoding: %s",
                                        under_name.c_str(),
                                        e.what());
                    continue;
                }
                return true;
            }
        }
    };

    std::unique_ptr<DirectoryTraverser> FileSystem::create_traverser(StringRef path)
    {
        if (path.empty())
            throwVFSException(EINVAL);
        return securefs::make_unique<LiteDirectoryTraverser>(
            m_root->create_traverser(translate_path(path, false)), &this->m_name_encryptor);
    }

#ifdef __APPLE__
    ssize_t
    FileSystem::getxattr(const char* path, const char* name, void* buf, size_t size) noexcept
    {
        if (!buf)
        {
            return m_root->getxattr(translate_path(path, false).c_str(), name, nullptr, 0);
        }

        try
        {
            auto iv_size = m_iv_size;
            auto mac_size = AESGCMCryptStream::get_mac_size();
            auto underbuf = securefs::make_unique_array<byte>(size + iv_size + mac_size);
            ssize_t readlen = m_root->getxattr(translate_path(path, false).c_str(),
                                               name,
                                               underbuf.get(),
                                               size + iv_size + mac_size);
            if (readlen <= 0)
                return readlen;
            if (readlen <= iv_size + mac_size)
                return -EIO;
            bool success
                = m_xattr_dec.DecryptAndVerify(static_cast<byte*>(buf),
                                               underbuf.get() + readlen - mac_size,
                                               mac_size,
                                               underbuf.get(),
                                               static_cast<int>(iv_size),
                                               nullptr,
                                               0,
                                               underbuf.get() + iv_size,
                                               static_cast<size_t>(readlen) - iv_size - mac_size);
            if (!success)
            {
                global_logger->error("Encrypted extended attribute for file %s and name %s fails "
                                     "ciphertext integrity check",
                                     path,
                                     name);
                return -EIO;
            }
            return readlen - iv_size - mac_size;
        }
        catch (const std::exception& e)
        {
            global_logger->error("Error decrypting extended attribute for file %s and name %s (%s)",
                                 path,
                                 name,
                                 e.what());
            return -EIO;
        }
    }

    int FileSystem::setxattr(
        const char* path, const char* name, void* buf, size_t size, int flags) noexcept
    {
        try
        {
            auto iv_size = m_iv_size;
            auto mac_size = AESGCMCryptStream::get_mac_size();
            auto underbuf = securefs::make_unique_array<byte>(size + iv_size + mac_size);
            generate_random(underbuf.get(), iv_size);
            m_xattr_enc.EncryptAndAuthenticate(underbuf.get() + iv_size,
                                               underbuf.get() + iv_size + size,
                                               mac_size,
                                               underbuf.get(),
                                               static_cast<int>(iv_size),
                                               nullptr,
                                               0,
                                               static_cast<const byte*>(buf),
                                               size);
            return m_root->setxattr(translate_path(path, false).c_str(),
                                    name,
                                    underbuf.get(),
                                    size + iv_size + mac_size,
                                    flags);
        }
        catch (const std::exception& e)
        {
            global_logger->error("Error encrypting extended attribute for file %s and name %s (%s)",
                                 path,
                                 name,
                                 e.what());
            return -EIO;
        }
    }
#endif
}
}
