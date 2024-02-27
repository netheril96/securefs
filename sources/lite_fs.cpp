#include "lite_fs.h"
#include "constants.h"
#include "lock_guard.h"
#include "logger.h"

#include <cryptopp/base32.h>

#include <cerrno>
#include <mutex>

namespace securefs
{
namespace lite
{

    File::~File() {}

    void File::fstat(struct fuse_stat* stat)
    {
        m_file_stream->fstat(stat);
        stat->st_size = AESGCMCryptStream::calculate_real_size(
            stat->st_size, m_crypt_stream->get_block_size(), m_crypt_stream->get_iv_size());
    }

    FileSystem::FileSystem(std::shared_ptr<const securefs::OSService> root,
                           const key_type& name_key,
                           const key_type& content_key,
                           const key_type& xattr_key,
                           const key_type& padding_key,
                           unsigned block_size,
                           unsigned iv_size,
                           unsigned max_padding_size,
                           unsigned flags)
        : m_name_encryptor()
        , m_content_key(content_key)
        , m_padding_aes(padding_key.data(), padding_key.size())
        , m_root(std::move(root))
        , m_block_size(block_size)
        , m_iv_size(iv_size)
        , m_max_padding_size(max_padding_size)
        , m_flags(flags)
    {
        byte null_iv[12] = {0};
        m_xattr_enc.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        m_xattr_dec.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        if (!(m_flags & kOptionNoNameTranslation))
        {
            m_name_encryptor = std::make_shared<AES_SIV>(name_key.data(), name_key.size());
        }
    }

    FileSystem::~FileSystem() {}

    InvalidFilenameException::~InvalidFilenameException() {}
    std::string InvalidFilenameException::message() const
    {
        return strprintf("Invalid filename \"%s\"", m_filename.c_str());
    }

    std::string encrypt_path(AES_SIV& encryptor, StringRef path)
    {
        byte buffer[2032];
        std::string result;
        result.reserve((path.size() * 8 + 4) / 5);
        size_t last_nonseparator_index = 0;
        std::string encoded_part;

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
                    base32_encode(buffer, slice_size + AES_SIV::IV_SIZE, encoded_part);
                    result.append(encoded_part);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    std::string decrypt_path(AES_SIV& decryptor, StringRef path)
    {
        byte string_buffer[2032];
        std::string result, decoded_part;
        result.reserve(path.size() * 5 / 8 + 10);
        size_t last_nonseparator_index = 0;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;

                    base32_decode(slice, slice_size, decoded_part);
                    if (decoded_part.size() >= sizeof(string_buffer))
                        throwVFSException(ENAMETOOLONG);

                    bool success
                        = decryptor.decrypt_and_verify(&decoded_part[AES_SIV::IV_SIZE],
                                                       decoded_part.size() - AES_SIV::IV_SIZE,
                                                       nullptr,
                                                       0,
                                                       string_buffer,
                                                       &decoded_part[0]);
                    if (!success)
                        throw InvalidFilenameException(path.to_string());
                    result.append((const char*)string_buffer,
                                  decoded_part.size() - AES_SIV::IV_SIZE);
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
            std::string str = !m_name_encryptor
                ? path.to_string()
                : lite::encrypt_path(
                    *m_name_encryptor,
                    transform(path, m_flags & kOptionCaseFoldFileName, m_flags & kOptionNFCFileName)
                        .get());
            if (!preserve_leading_slash && !str.empty() && str[0] == '/')
            {
                str.erase(str.begin());
            }
            TRACE_LOG("Translate path %s into %s", path.c_str(), str.c_str());
            return str;
        }
    }

    AutoClosedFile FileSystem::open(StringRef path, int flags, fuse_mode_t mode)
    {
        if (flags & O_APPEND)
        {
            flags &= ~((unsigned)O_APPEND);
            // Clear append flags. Workaround for FUSE bug.
            // See https://github.com/netheril96/securefs/issues/58.
        }

        // Files cannot be opened write-only because the header must be read in order to derive the
        // session key
        if ((flags & O_ACCMODE) == O_WRONLY)
        {
            flags = (flags & ~O_ACCMODE) | O_RDWR;
        }
        if ((flags & O_CREAT))
        {
            mode |= S_IRUSR;
        }
        auto file_stream = m_root->open_file_stream(translate_path(path, false), flags, mode);
        AutoClosedFile fp(new File(file_stream,
                                   m_content_key,
                                   m_block_size,
                                   m_iv_size,
                                   (m_flags & kOptionNoAuthentication) == 0,
                                   m_max_padding_size,
                                   &m_padding_aes));
        if (flags & O_TRUNC)
        {
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(0);
        }
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
            // This is a workaround for Interix symbolic links on NTFS volumes
            // (https://github.com/netheril96/securefs/issues/43).

            // 'buf->st_size' is the expected link size, but on NTFS volumes the link starts with
            // 'IntxLNK\1' followed by the UTF-16 encoded target.
            std::string buffer(buf->st_size, '\0');
            ssize_t link_size = m_root->readlink(enc_path, &buffer[0], buffer.size());
            if (link_size != buf->st_size && link_size != (buf->st_size - 8) / 2)
                throwVFSException(EIO);

            if (m_name_encryptor)
            {
                // Resize to actual size
                buffer.resize(static_cast<size_t>(link_size));
                auto resolved = decrypt_path(*m_name_encryptor, buffer);
                buf->st_size = resolved.size();
            }
            else
            {
                buf->st_size = link_size;
            }
            break;
        }
        case S_IFDIR:
            break;
        case S_IFREG:
            if (buf->st_size > 0)
            {
                if (m_max_padding_size <= 0)
                {
                    buf->st_size = AESGCMCryptStream::calculate_real_size(
                        buf->st_size, m_block_size, m_iv_size);
                }
                else
                {
                    try
                    {
                        auto fs = m_root->open_file_stream(enc_path, O_RDONLY, 0);
                        AESGCMCryptStream stream(std::move(fs),
                                                 m_content_key,
                                                 m_block_size,
                                                 m_iv_size,
                                                 (m_flags & kOptionNoAuthentication) == 0,
                                                 m_max_padding_size,
                                                 &m_padding_aes);
                        buf->st_size = stream.size();
                    }
                    catch (const std::exception& e)
                    {
                        ERROR_LOG("Encountered exception %s when opening file %s for read: %s",
                                  get_type_name(e).get(),
                                  path.c_str(),
                                  e.what());
                    }
                }
            }
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
        if (!(mode & S_IRUSR))
        {
            WARN_LOG("Change the mode of file %s to 0%o which denies user read access. "
                     "Mysterious bugs will occur.",
                     path.c_str(),
                     static_cast<unsigned>(mode));
        }
        m_root->chmod(translate_path(path, false), mode);
    }

    void FileSystem::chown(StringRef path, fuse_uid_t uid, fuse_gid_t gid)
    {
        m_root->chown(translate_path(path, false), uid, gid);
    }

    size_t FileSystem::readlink(StringRef path, char* buf, size_t size)
    {
        if (size <= 0)
            return size;

        auto max_size = size / 5 * 8 + 32;
        auto underbuf = securefs::make_unique_array<char>(max_size);
        memset(underbuf.get(), 0, max_size);
        m_root->readlink(translate_path(path, false), underbuf.get(), max_size - 1);
        std::string resolved
            = m_name_encryptor ? decrypt_path(*m_name_encryptor, underbuf.get()) : underbuf.get();
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

    class ABSL_LOCKABLE LiteDirectory final : public Directory
    {
    private:
        std::string m_path;
        std::unique_ptr<DirectoryTraverser> m_underlying_traverser ABSL_GUARDED_BY(*this);

        // Nullable. When null, the name isn't translated.
        std::shared_ptr<AES_SIV> m_name_encryptor;
        unsigned m_block_size, m_iv_size;

    public:
        explicit LiteDirectory(
            std::string path,
            std::unique_ptr<DirectoryTraverser> underlying_traverser,
            std::shared_ptr<AES_SIV>
                name_encryptor,    // Nullable. When null, the name isn't translated.
            unsigned block_size,
            unsigned iv_size)
            : m_path(std::move(path))
            , m_underlying_traverser(std::move(underlying_traverser))
            , m_name_encryptor(std::move(name_encryptor))
            , m_block_size(block_size)
            , m_iv_size(iv_size)
        {
        }

        StringRef path() const override { return m_path; }

        void rewind() override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            m_underlying_traverser->rewind();
        }

        bool next(std::string* name, struct fuse_stat* stbuf) override
            ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            std::string under_name, decoded_bytes;

            while (1)
            {
                if (!m_underlying_traverser->next(&under_name, stbuf))
                    return false;
                if (!name)
                    return true;

                if (under_name.empty())
                    continue;
                if (under_name == "." || under_name == "..")
                {
                    if (name)
                        name->swap(under_name);
                    return true;
                }
                if (!m_name_encryptor)
                {
                    // Plain text name mode
                    if (name)
                        name->swap(under_name);
                    if (stbuf)
                        stbuf->st_size = AESGCMCryptStream::calculate_real_size(
                            stbuf->st_size, m_block_size, m_iv_size);
                    return true;
                }
                if (under_name[0] == '.')
                    continue;
                try
                {
                    base32_decode(under_name.data(), under_name.size(), decoded_bytes);
                    if (decoded_bytes.size() <= AES_SIV::IV_SIZE)
                    {
                        WARN_LOG("Skipping too small encrypted filename %s", under_name.c_str());
                        continue;
                    }
                    name->assign(decoded_bytes.size() - AES_SIV::IV_SIZE, '\0');
                    bool success
                        = m_name_encryptor->decrypt_and_verify(&decoded_bytes[AES_SIV::IV_SIZE],
                                                               name->size(),
                                                               nullptr,
                                                               0,
                                                               &(*name)[0],
                                                               &decoded_bytes[0]);
                    if (!success)
                    {
                        WARN_LOG("Skipping filename %s (decrypted to %s) since it fails "
                                 "authentication check",
                                 under_name.c_str(),
                                 name->c_str());
                        continue;
                    }
                    if (stbuf)
                        stbuf->st_size = AESGCMCryptStream::calculate_real_size(
                            stbuf->st_size, m_block_size, m_iv_size);
                }
                catch (const std::exception& e)
                {
                    WARN_LOG("Skipping filename %s due to exception in decoding: %s",
                             under_name.c_str(),
                             e.what());
                    continue;
                }
                return true;
            }
        }
    };

    std::unique_ptr<Directory> FileSystem::opendir(StringRef path)
    {
        if (path.empty())
            throwVFSException(EINVAL);
        return securefs::make_unique<LiteDirectory>(
            path.to_string(),
            m_root->create_traverser(translate_path(path, false)),
            this->m_name_encryptor,
            m_block_size,
            m_iv_size);
    }

    Base::~Base() {}

#ifdef __APPLE__
    ssize_t
    FileSystem::getxattr(const char* path, const char* name, void* buf, size_t size) noexcept
    {
        auto iv_size = m_iv_size;
        auto mac_size = AESGCMCryptStream::get_mac_size();
        if (!buf)
        {
            auto rc = m_root->getxattr(translate_path(path, false).c_str(), name, nullptr, 0);
            if (rc < 0)
            {
                return rc;
            }
            if (rc <= iv_size + mac_size)
            {
                return 0;
            }
            return rc - iv_size - mac_size;
        }

        try
        {
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
                ERROR_LOG("Encrypted extended attribute for file %s and name %s fails "
                          "ciphertext integrity check",
                          path,
                          name);
                return -EIO;
            }
            return readlen - iv_size - mac_size;
        }
        catch (const std::exception& e)
        {
            ERROR_LOG("Error decrypting extended attribute for file %s and name %s (%s)",
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
            ERROR_LOG("Error encrypting extended attribute for file %s and name %s (%s)",
                      path,
                      name,
                      e.what());
            return -EIO;
        }
    }

#endif
}    // namespace lite
}    // namespace securefs
