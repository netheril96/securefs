#include "lite_fs.h"

#include <cryptopp/base32.h>

namespace securefs
{
namespace lite
{
    File::File(std::string name,
               std::shared_ptr<securefs::FileStream> file_stream,
               const key_type& master_key,
               unsigned block_size,
               unsigned iv_size,
               bool check)
        : m_crypt_stream(file_stream, master_key, block_size, iv_size, check)
        , m_name(std::move(name))
        , m_file_stream(file_stream)
        , m_open_count(0)
    {
    }

    File::~File() {}

    void File::fstat(FUSE_STAT* stat)
    {
        m_file_stream->fstat(stat);
        stat->st_size = AESGCMCryptStream::calculate_real_size(
            stat->st_size, m_crypt_stream.get_block_size(), m_crypt_stream.get_iv_size());
    }

    FileSystem::FileSystem(std::shared_ptr<securefs::OSService> root,
                           const key_type& name_key,
                           const key_type& content_key,
                           const key_type& xattr_key,
                           unsigned block_size,
                           unsigned iv_size,
                           bool check)
        : m_name_encryptor(name_key.data(), name_key.size())
        , m_content_key(content_key)
        , m_root(std::move(root))
        , m_block_size(block_size)
        , m_iv_size(iv_size)
        , m_check(check)
    {
        byte null_iv[12] = {0};
        m_xattr_enc.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        m_xattr_dec.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
    }

    FileSystem::~FileSystem() {}

    void FileSystem::close(File* f)
    {
        if (!f)
            return;

        if (f->decrease_open_count() <= 0)
        {
            auto iter = m_opened_files.find(f->name());
            if (iter != m_opened_files.end())
                m_opened_files.erase(iter);
            delete f;
        }
    }

    InvalidFilenameException::~InvalidFilenameException() {}
    std::string InvalidFilenameException::message() const
    {
        return strprintf("Invalid filename \"%s\"", m_filename.c_str());
    }

    std::string encrypt_path(AES_SIV& encryptor, const std::string& path)
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
                    encryptor.encrypt_and_authenticate(slice,
                                                       slice_size,
                                                       path.data(),
                                                       last_nonseparator_index,
                                                       buffer + AES_SIV::IV_SIZE,
                                                       buffer);
                    CryptoPP::Base32Encoder encoder;
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

    std::string decrypt_path(AES_SIV& decryptor, const std::string& path)
    {
        byte buffer[2032];
        byte string_buffer[2032];
        std::string result;
        result.reserve(path.size() * 5 / 8);
        size_t last_nonseparator_index = 0;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;

                    CryptoPP::Base32Decoder decoder;
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
                                                                result.data(),
                                                                result.size(),
                                                                string_buffer,
                                                                buffer);
                    if (!success)
                        throw InvalidFilenameException(path);
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

    std::string FileSystem::translate_path(const std::string& path, bool preserve_leading_slash)
    {
        if (path.empty())
            return {};
        if (path == "/")
        {
            if (preserve_leading_slash)
                return path;
            return ".";
        }
        auto str = lite::encrypt_path(m_name_encryptor, path);
        if (!preserve_leading_slash && !str.empty() && str[0] == '/')
        {
            str.erase(str.begin());
        }
        return str;
    }

    AutoClosedFile FileSystem::open(const std::string& path, int flags)
    {
        if ((flags & O_CREAT) | (flags & O_APPEND))
            throwVFSException(ENOTSUP);

        AutoClosedFile result(nullptr, FSCCloser(this));
        auto iter = m_opened_files.find(path);
        if (iter != m_opened_files.end())
        {
            iter->second->increase_open_count();
            result.reset(iter->second);
        }
        else
        {
            auto file_stream = m_root->open_file_stream(translate_path(path, false), O_RDWR, 0644);
            auto fp = securefs::make_unique<File>(
                path, file_stream, m_content_key, m_block_size, m_iv_size, m_check);
            fp->increase_open_count();
            File* fp_pointer = fp.get();
            m_opened_files[path] = fp.release();
            result.reset(fp_pointer);
        }
        if (flags & O_TRUNC)
            result->resize(0);
        return result;
    }

    AutoClosedFile FileSystem::create(const std::string& path, mode_t mode)
    {
        if (m_opened_files.find(path) != m_opened_files.end())
            throwVFSException(EEXIST);
        auto file_stream = m_root->open_file_stream(
            translate_path(path, false), O_RDWR | O_EXCL | O_CREAT, mode);
        auto fp = securefs::make_unique<File>(
            path, file_stream, m_content_key, m_block_size, m_iv_size, m_check);
        fp->increase_open_count();
        File* fp_pointer = fp.get();
        m_opened_files[path] = fp.release();
        return AutoClosedFile(fp_pointer, FSCCloser(this));
    }

    void FileSystem::stat(const std::string& path, FUSE_STAT* buf)
    {
        auto enc_path = translate_path(path, false);
        m_root->stat(enc_path, buf);
        if (buf->st_size <= 0)
            return;
        switch (buf->st_mode & S_IFMT)
        {
        case S_IFLNK:
        {
            auto iter = m_resolved_symlinks.find(path);
            if (iter != m_resolved_symlinks.end())
            {
                buf->st_size = iter->second.size();
            }
            else
            {
                std::string buffer(buf->st_size, '\0');
                if (m_root->readlink(enc_path, &buffer[0], buffer.size()) != buf->st_size)
                    throwVFSException(EIO);
                auto resolved = decrypt_path(m_name_encryptor, buffer);
                buf->st_size = resolved.size();
                m_resolved_symlinks.emplace(path, std::move(resolved));
            }
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
    }

    void FileSystem::mkdir(const std::string& path, mode_t mode)
    {
        m_root->mkdir(translate_path(path, false), mode);
    }

    void FileSystem::rmdir(const std::string& path)
    {
        m_root->remove_directory(translate_path(path, false));
    }

    void FileSystem::rename(const std::string& from, const std::string& to)
    {
        m_root->rename(translate_path(from, false), translate_path(to, false));
    }

    void FileSystem::chmod(const std::string& path, mode_t mode)
    {
        m_root->chmod(translate_path(path, false), mode);
    }

    size_t FileSystem::readlink(const std::string& path, char* buf, size_t size)
    {
        if (size <= 0)
            return size;

        auto iter = m_resolved_symlinks.find(path);
        if (iter == m_resolved_symlinks.end())
        {
            FUSE_STAT st;
            this->stat(path, &st);
            iter = m_resolved_symlinks.find(path);
            if (iter == m_resolved_symlinks.end())
                throwVFSException(EIO);
        }

        auto read_size = std::min(iter->second.size(), size - 1);
        memcpy(buf, iter->second.data(), read_size);
        buf[read_size] = '\0';
        return read_size;
    }

    void FileSystem::symlink(const std::string& to, const std::string& from)
    {
        auto eto = translate_path(to, true), efrom = translate_path(from, false);
        m_root->symlink(eto, efrom);
        m_resolved_symlinks[efrom] = std::move(eto);
    }

    void FileSystem::utimens(const std::string& path, const timespec* ts)
    {
        AutoClosedFile fp = open(path, O_RDONLY);
        std::lock_guard<File> lg(*fp);
        fp->utimens(ts);
    }

    void FileSystem::unlink(const std::string& path)
    {
        m_root->remove_file(translate_path(path, false));
        m_opened_files.erase(path);
        m_resolved_symlinks.erase(path);
    }

    void FileSystem::truncate(const std::string& path, offset_type len)
    {
        AutoClosedFile fp = open(path, O_RDONLY);
        std::lock_guard<File> lg(*fp);
        fp->resize(len);
    }

    void FileSystem::statvfs(struct statvfs* buf) { m_root->statfs(buf); }

    void FileSystem::traverse_directory(
        const std::string& path,
        const OSService::traverse_callback& callback,
        const std::function<void(const std::string&)> decoding_error_handler)
    {
        if (path.empty())
            return;
        const std::string& prefix = (path.back() == '/' ? path : path + '/');

        auto wrapped_callback = [&callback, &decoding_error_handler, &prefix, this](
            const std::string& name, mode_t mode) -> bool {
            if (name.empty() || name.front() == '.')
                return true;
            try
            {
                CryptoPP::Base32Decoder decoder;
                decoder.Put(reinterpret_cast<const byte*>(name.data()), name.size());
                decoder.MessageEnd();

                byte buffer[2000];
                auto size = decoder.MaxRetrievable();
                if (size > sizeof(buffer) || size <= AES_SIV::IV_SIZE)
                {
                    decoding_error_handler(name);
                    return true;
                }
                decoder.Get(buffer, sizeof(buffer));
                std::string decoded_name(size - AES_SIV::IV_SIZE, '\0');
                bool success = this->m_name_encryptor.decrypt_and_verify(buffer + AES_SIV::IV_SIZE,
                                                                         size - AES_SIV::IV_SIZE,
                                                                         prefix.data(),
                                                                         prefix.size(),
                                                                         &decoded_name[0],
                                                                         buffer);
                if (!success)
                {
                    decoding_error_handler(name);
                    return true;
                }
                return callback(decoded_name, mode);
            }
            catch (...)
            {
                decoding_error_handler(name);
                return true;
            }
        };

        m_root->traverse(translate_path(path, false), wrapped_callback);
    }
}
}
