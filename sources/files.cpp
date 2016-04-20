#include "files.h"
#include "utils.h"
#include "xattr_compat.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

#include <cryptopp/secblock.h>

#include <sys/types.h>

namespace securefs
{

FileBase::FileBase(int data_fd,
                   int meta_fd,
                   const key_type& key_,
                   const id_type& id_,
                   bool check,
                   unsigned block_size,
                   unsigned iv_size)
    : m_refcount(1)
    , m_header()
    , m_id(id_)
    , m_data_fd(data_fd)
    , m_meta_fd(meta_fd)
    , m_dirty(false)
    , m_check(check)
    , m_stream()
    , m_removed(false)
{
    auto data_stream = std::make_shared<POSIXFileStream>(data_fd);
    auto meta_stream = std::make_shared<POSIXFileStream>(meta_fd);

    key_type data_key, meta_key;
    byte generated_keys[KEY_LENGTH * 3];
    hkdf(key_.data(),
         key_.size(),
         nullptr,
         0,
         id_.data(),
         id_.size(),
         generated_keys,
         sizeof(generated_keys));
    memcpy(data_key.data(), generated_keys, KEY_LENGTH);
    memcpy(meta_key.data(), generated_keys + KEY_LENGTH, KEY_LENGTH);
    memcpy(m_key.data(), generated_keys + 2 * KEY_LENGTH, KEY_LENGTH);
    auto crypt = make_cryptstream_aes_gcm(std::move(data_stream),
                                          std::move(meta_stream),
                                          data_key,
                                          meta_key,
                                          id_,
                                          check,
                                          block_size,
                                          iv_size);

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
        set_num_free_page(0);
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

int FileBase::get_stat_type()
{
    struct stat st;
    this->stat(&st);
    return type_for_mode(st.st_mode & S_IFMT);
}

void FileBase::stat(struct stat* st)
{
    if (!st)
        throw OSException(EFAULT);
    int rc = ::fstat(file_descriptor(), st);
    if (rc < 0)
        throw UnderlyingOSException(errno, "stat");

    st->st_uid = get_uid();
    st->st_gid = get_gid();
    st->st_nlink = get_nlink();
    st->st_mode = get_mode();
    st->st_size = m_stream->size();
    auto blk_sz = m_stream->optimal_block_size();
    if (blk_sz > 1 && blk_sz < std::numeric_limits<decltype(st->st_blksize)>::max())
    {
        st->st_blksize = static_cast<decltype(st->st_blksize)>(blk_sz);
        st->st_blocks = (st->st_size + st->st_blksize - 1) / st->st_blksize;
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

// These values cannot be changed, because OS X has a peculiar restriction where the xattr value for
// com.apple.FinderInfo is fixed at 32 bytes.
static const ssize_t XATTR_IV_LENGTH = 16, XATTR_MAC_LENGTH = 16;

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

static ssize_t fgetxattr_wrapper(int fd, const char* name, void* value, size_t size)
{
#ifdef __APPLE__
    return ::fgetxattr(fd, name, value, size, 0, 0);
#else
    return ::fgetxattr(fd, name, value, size);
#endif
}

ssize_t FileBase::getxattr(const char* name, char* value, size_t size)
{
    if (!name)
        throw OSException(EFAULT);

    auto true_size = fgetxattr_wrapper(file_descriptor(), name, value, size);
    if (true_size < 0)
        throw OSException(errno);
    if (!value)
        return true_size;

    byte meta[XATTR_IV_LENGTH + XATTR_MAC_LENGTH];
    auto true_meta_size = fgetxattr_wrapper(m_meta_fd, name, meta, sizeof(meta));
    if (true_meta_size < 0)
    {
        if (errno == ERANGE)
            errno = EIO;
        throw OSException(errno);
    }

    auto name_len = strlen(name);
    std::unique_ptr<byte[]> header(new byte[name_len + ID_LENGTH]);
    memcpy(header.get(), get_id().data(), ID_LENGTH);
    memcpy(header.get() + ID_LENGTH, name, name_len);

    byte* iv = meta;
    byte* mac = meta + XATTR_IV_LENGTH;
    byte* ciphertext = reinterpret_cast<byte*>(value);

    bool success = aes_gcm_decrypt(ciphertext,
                                   true_size,
                                   header.get(),
                                   name_len + ID_LENGTH,
                                   get_key().data(),
                                   get_key().size(),
                                   iv,
                                   XATTR_IV_LENGTH,
                                   mac,
                                   XATTR_MAC_LENGTH,
                                   value);
    if (m_check && !success)
        throw XattrVerificationException(get_id(), name);
    return true_size;
}

static int fsetxattr_wrapper(int fd, const char* name, void* value, size_t size, int flags)
{
#ifdef __APPLE__
    return ::fsetxattr(fd, name, value, size, 0, flags);
#else
    return ::fsetxattr(fd, name, value, size, flags);
#endif
}

void FileBase::setxattr(const char* name, const char* value, size_t size, int flags)
{
    if (!name || !value)
        throw OSException(EFAULT);

    std::unique_ptr<byte[]> buffer(new byte[size]);
    byte* ciphertext = buffer.get();

    byte meta[XATTR_MAC_LENGTH + XATTR_IV_LENGTH];
    byte* iv = meta;
    byte* mac = iv + XATTR_IV_LENGTH;
    generate_random(iv, XATTR_IV_LENGTH);

    auto name_len = strlen(name);
    std::unique_ptr<byte[]> header(new byte[name_len + ID_LENGTH]);
    memcpy(header.get(), get_id().data(), ID_LENGTH);
    memcpy(header.get() + ID_LENGTH, name, name_len);

    aes_gcm_encrypt(value,
                    size,
                    header.get(),
                    name_len + ID_LENGTH,
                    get_key().data(),
                    get_key().size(),
                    iv,
                    XATTR_IV_LENGTH,
                    mac,
                    XATTR_MAC_LENGTH,
                    ciphertext);

    auto rc = fsetxattr_wrapper(file_descriptor(), name, ciphertext, size, flags);
    if (rc < 0)
        throw OSException(errno);
    rc = fsetxattr_wrapper(m_meta_fd, name, meta, sizeof(meta), flags);
    if (rc < 0)
        throw OSException(errno);
}

void FileBase::removexattr(const char* name)
{
#ifdef __APPLE__
    auto rc = ::fremovexattr(file_descriptor(), name, 0);
#else
    auto rc = ::fremovexattr(file_descriptor(), name);
#endif
    if (rc < 0)
        throw OSException(errno);
}

void SimpleDirectory::initialize()
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
        buffer[MAX_FILENAME_LENGTH] = 0;    // Set the null terminator in case the data is corrupted
        name = buffer;
        memcpy(value.first.data(), buffer + Directory::MAX_FILENAME_LENGTH + 1, ID_LENGTH);
        value.second = from_little_endian<uint32_t>(buffer + sizeof(buffer) - sizeof(uint32_t));
        m_table.emplace(std::move(name), std::move(value));
        off += sizeof(buffer);
    }
}

bool SimpleDirectory::get_entry(const std::string& name, id_type& id, int& type)
{
    auto it = m_table.find(name);
    if (it == m_table.end())
        return false;
    memcpy(id.data(), it->second.first.data(), id.size());
    type = it->second.second;
    return true;
}

bool SimpleDirectory::add_entry(const std::string& name, const id_type& id, int type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throw OSException(ENAMETOOLONG);
    auto rv = m_table.emplace(name, std::make_pair(id, type));
    if (rv.second)
        m_dirty = true;
    return rv.second;
}

bool SimpleDirectory::remove_entry(const std::string& name, id_type& id, int& type)
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

void SimpleDirectory::subflush()
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

SimpleDirectory::~SimpleDirectory()
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
}
