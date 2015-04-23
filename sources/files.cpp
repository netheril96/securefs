#include "files.h"
#include "utils.h"

#include <unordered_map>
#include <utility>
#include <algorithm>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/secblock.h>

#include <sys/types.h>
#ifdef __APPLE__
#include <sys/xattr.h>
#else
#include <attr/xattr.h>
#endif

namespace securefs
{

FileBase::FileBase(int data_fd, int meta_fd, std::shared_ptr<const SecureParam> param, bool check)
    : m_lock()
    , m_refcount(1)
    , m_header()
    , m_param(param)
    , m_data_fd(data_fd)
    , m_dirty(false)
    , m_check(check)
    , m_stream()
    , m_removed(false)
{
    if (!param)
        NULL_EXCEPT();
    auto data_stream = std::make_shared<POSIXFileStream>(data_fd);
    auto meta_stream = std::make_shared<POSIXFileStream>(meta_fd);
    auto crypt
        = make_cryptstream_aes_gcm(std::move(data_stream), std::move(meta_stream), param, check);
    m_stream = crypt.first;
    m_header = crypt.second;
    read_header();
}

void FileBase::read_header()
{
    byte header[sizeof(m_flags)];
    auto rc = m_header->read_header(header, sizeof(header));
    if (!rc)
    {
        memset(m_flags, 0xFF, sizeof(m_flags));
    }
    else
    {
        const byte* ptr = header;
        for (auto&& f : m_flags)
        {
            f = from_little_endian<decltype(f)>(ptr);
            ptr += sizeof(f);
        }
    }
}

FileBase::~FileBase() {}

void FileBase::flush()
{
    this->subflush();
    if (m_dirty)
    {
        byte header[sizeof(m_flags)];
        byte* ptr = header;
        for (auto&& f : m_flags)
        {
            to_little_endian(f, ptr);
            ptr += sizeof(f);
        }
        m_header->write_header(header, sizeof(header));
        m_dirty = false;
    }
    m_header->flush_header();
    m_stream->flush();
}

static const ssize_t XATTR_IV_LENGTH = 32, XATTR_MAC_LENGTH = 16;

ssize_t FileBase::listxattr(char* buffer, size_t size)
{
#ifdef __APPLE__
    auto rc = ::flistxattr(file_descriptor(), buffer, size, 0);
#else
    auto rc = ::flistxattr(file_descriptor(), buffer, size);
#endif
    if (rc < 0)
        throw OSException(errno);
    return rc;
}

ssize_t FileBase::getxattr(const char* name, char* value, size_t size)
{
    ssize_t encrypted_length;
#ifdef __APPLE__
    encrypted_length = ::fgetxattr(file_descriptor(), name, nullptr, 0, 0, 0);
#else
    encrypted_length = ::fgetxattr(file_descriptor(), name, nullptr, 0);
#endif

    if (encrypted_length < 0)
        throw OSException(errno);

    if (encrypted_length <= XATTR_MAC_LENGTH + XATTR_IV_LENGTH)
        return 0;

    if (!value)
        return encrypted_length - XATTR_MAC_LENGTH - XATTR_IV_LENGTH;

    std::unique_ptr<byte[]> read_buffer(new byte[encrypted_length]);
#ifdef __APPLE__
    auto rc = ::fgetxattr(file_descriptor(), name, read_buffer.get(), encrypted_length, 0, 0);
#else
    auto rc = ::fgetxattr(file_descriptor(), name, read_buffer.get(), encrypted_length);
#endif

    if (rc < 0)
        throw OSException(errno);
    if (rc != encrypted_length)
        throw OSException(EBUSY);

    auto name_len = strlen(name);
    std::unique_ptr<byte[]> header(new byte[name_len + ID_LENGTH]);
    memcpy(header.get(), get_id().data(), ID_LENGTH);
    memcpy(header.get() + ID_LENGTH, name, name_len);

    byte* iv = read_buffer.get();
    byte* mac = iv + XATTR_IV_LENGTH;
    byte* ciphertext = mac + XATTR_MAC_LENGTH;
    auto length = static_cast<size_t>(rc - XATTR_IV_LENGTH - XATTR_MAC_LENGTH);

    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(get_key().data(), KEY_LENGTH, iv, XATTR_IV_LENGTH);
    bool success = false;

    if (length <= size)
    {
        success = dec.DecryptAndVerify(reinterpret_cast<byte*>(value),
                                       mac,
                                       XATTR_MAC_LENGTH,
                                       iv,
                                       XATTR_IV_LENGTH,
                                       header.get(),
                                       name_len + ID_LENGTH,
                                       ciphertext,
                                       length);
    }
    else
    {
        CryptoPP::AlignedSecByteBlock buffer(length);
        success = dec.DecryptAndVerify(buffer.data(),
                                       mac,
                                       XATTR_MAC_LENGTH,
                                       iv,
                                       XATTR_IV_LENGTH,
                                       header.get(),
                                       name_len + ID_LENGTH,
                                       ciphertext,
                                       length);
        memcpy(value, buffer.data(), size);
    }

    if (m_check && !success)
        throw XattrVerificationException(get_id(), name);
    return length;
}

void FileBase::setxattr(const char* name, const char* value, size_t size, int flags)
{
    std::unique_ptr<byte[]> buffer(new byte[size + XATTR_IV_LENGTH + XATTR_MAC_LENGTH]);
    byte* iv = buffer.get();
    generate_random(iv, XATTR_IV_LENGTH);
    byte* mac = iv + XATTR_IV_LENGTH;
    byte* ciphertext = mac + XATTR_MAC_LENGTH;

    auto name_len = strlen(name);
    std::unique_ptr<byte[]> header(new byte[name_len + ID_LENGTH]);
    memcpy(header.get(), get_id().data(), ID_LENGTH);
    memcpy(header.get() + ID_LENGTH, name, name_len);

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(get_key().data(), KEY_LENGTH, iv, XATTR_IV_LENGTH);
    enc.EncryptAndAuthenticate(ciphertext,
                               mac,
                               XATTR_MAC_LENGTH,
                               iv,
                               XATTR_IV_LENGTH,
                               header.get(),
                               name_len + ID_LENGTH,
                               reinterpret_cast<const byte*>(value),
                               size);
#ifdef __APPLE__
    auto rc = ::fsetxattr(
        file_descriptor(), name, buffer.get(), size + XATTR_IV_LENGTH + XATTR_MAC_LENGTH, 0, flags);
#else
    auto rc = ::fsetxattr(
        file_descriptor(), name, buffer.get(), size + XATTR_IV_LENGTH + XATTR_MAC_LENGTH, flags);
#endif
    if (rc < 0)
        throw OSException(errno);
}

namespace internal
{
    class SimpleDirectory : public Directory
    {
    private:
        std::unordered_map<std::string, std::pair<id_type, int>> m_table;
        bool m_dirty;

    public:
        template <class... Args>
        explicit SimpleDirectory(Args&&... args)
            : Directory(std::forward<Args>(args)...)
        {
            char buffer[Directory::MAX_FILENAME_LENGTH + 1 + 32 + 4];
            offset_type off = 0;
            std::string name;
            std::pair<id_type, int> value;
            while (true)
            {
                auto rv = this->m_stream->read(buffer, off, sizeof(buffer));
                if (rv < sizeof(buffer))
                    break;
                buffer[MAX_FILENAME_LENGTH]
                    = 0;    // Set the null terminator in case the data is corrupted
                name = buffer;
                memcpy(value.first.data(), buffer + Directory::MAX_FILENAME_LENGTH + 1, ID_LENGTH);
                value.second
                    = from_little_endian<uint32_t>(buffer + sizeof(buffer) - sizeof(uint32_t));
                m_table.emplace(std::move(name), std::move(value));
                off += sizeof(buffer);
            }
        }

        bool get_entry(const std::string& name, id_type& id, int& type) override
        {
            auto it = m_table.find(name);
            if (it == m_table.end())
                return false;
            memcpy(id.data(), it->second.first.data(), id.size());
            type = it->second.second;
            return true;
        }

        bool add_entry(const std::string& name, const id_type& id, int type) override
        {
            if (name.size() > MAX_FILENAME_LENGTH)
                throw OSException(ENAMETOOLONG);
            auto rv = m_table.emplace(name, std::make_pair(id, type));
            if (rv.second)
                m_dirty = true;
            return rv.second;
        }

        bool remove_entry(const std::string& name, id_type& id, int& type) override
        {
            auto it = m_table.find(name);
            if (it == m_table.end())
                return false;
            memcpy(id.data(), it->second.first.data(), id.size());
            type = it->second.second;
            m_table.erase(it);
            m_dirty = true;
            return true;
        }

        void subflush() override
        {
            if (m_dirty)
            {
                m_stream->resize(0);
                char buffer[Directory::MAX_FILENAME_LENGTH + 1 + 32 + 4];
                offset_type off = 0;
                for (auto&& pair : m_table)
                {
                    memset(buffer, 0, sizeof(buffer));
                    if (pair.first.size() > MAX_FILENAME_LENGTH)
                        continue;
                    memcpy(buffer, pair.first.data(), pair.first.size());
                    memcpy(buffer + MAX_FILENAME_LENGTH + 1, pair.second.first.data(), ID_LENGTH);
                    to_little_endian(static_cast<uint32_t>(pair.second.second),
                                     buffer + sizeof(buffer) - sizeof(uint32_t));
                    this->m_stream->write(buffer, off, sizeof(buffer));
                    off += sizeof(buffer);
                }
                m_dirty = false;
            }
        }

        void iterate_over_entries(callback cb) override
        {
            for (const auto& pair : m_table)
            {
                if (!cb(pair.first, pair.second.first, pair.second.second))
                    break;
            }
        }

        bool empty() const override { return m_table.empty(); }

        ~SimpleDirectory()
        {
            try
            {
                flush();
            }
            catch (...)
            {
                // Ignore exceptions in destructor
            }
        }
    };
}

std::shared_ptr<Directory>
make_directory(int data_fd, int meta_fd, std::shared_ptr<const SecureParam> param, bool check)
{
    return std::make_shared<internal::SimpleDirectory>(data_fd, meta_fd, std::move(param), check);
}
}
