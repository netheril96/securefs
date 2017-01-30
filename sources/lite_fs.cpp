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
        , m_name(name)
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

    FileSystemContext::FileSystemContext(std::shared_ptr<securefs::OSService> root,
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

    FileSystemContext::~FileSystemContext() {}

#define PLACE_LOCK_GUARD() std::lock_guard<FileSystemContext> lkgd(*this)

    void FileSystemContext::close(File* f)
    {
        if (!f)
            return;

        PLACE_LOCK_GUARD();
        auto iter = m_opened_files.find(f->name());
        if (iter == m_opened_files.end())
            throwInvalidArgumentException("Closing a file not in the filesystem");
        if (iter->second.decrease_open_count() <= 0)
        {
            m_opened_files.erase(iter);
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

    std::string FileSystemContext::encrypt_path(const std::string& path)
    {
        return lite::encrypt_path(m_name_encryptor, path);
    }

    std::string FileSystemContext::decrypt_path(const std::string& path)
    {
        return lite::decrypt_path(m_name_encryptor, path);
    }

    AutoClosedFile FileSystemContext::open(const std::string& path, int flags, int mode)
    {
        auto iter = m_opened_files.find(path);
        if (iter != m_opened_files.end())
        {
            return AutoClosedFile(&iter->second, FSCCloser(this));
        }
    }
}
}
