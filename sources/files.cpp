#include "files.h"
#include "crypto.h"
#include "exceptions.h"
#include "myutils.h"
#include "stat_workaround.h"
#include "xattr_name.h"

#include <cryptopp/integer.h>
#include <cryptopp/secblock.h>

#include <utility>

#include <sys/types.h>

/**

 Layout of the header field in the metadata file:

 ----
 mode
----
 uid
 ----
 gid
 ----
 nlink
 ----
 root_page
 ----
 start_of_free_page
 ----
 num_free_page
 ----
 (unused)
 ----

 Each field is a 32-bit unsigned number. The last four field is unused for regular files.

 When store_time extension is enabled, the header field is enlarged to store the atime, mtime, and
ctime of the file.

The layout becomes
 ----
 mode
 ----
 uid
 ----
 gid
 ----
 nlink
 ----
 root_page
 ----
 start_of_free_page
 ----
 num_free_page
 ----

 atime

 ----

 mtime

 ----

 ctime

 ----

 birthtime

 ----
 (unused)
 ----

 Each time field is composed of three 32-bit integers, the first two compose the time in seconds
since epoch, and last one is the number of nanoseconds.
**/

namespace securefs
{
void FileBase::initialize_empty(uint32_t mode, uint32_t uid, uint32_t gid)
{
    if (uid == -1)
    {
        uid = OSService::get_default().getuid();
    }
    if (gid == -1)
    {
        gid = OSService::get_default().getgid();
    }
    m_flags[0] = mode;
    m_flags[1] = uid;
    m_flags[2] = gid;
    m_flags[3] = 1;
    m_flags[4] = static_cast<uint32_t>(-1);
    m_flags[5] = static_cast<uint32_t>(-1);
    m_flags[6] = 0;

    if (m_store_time)
    {
        OSService::get_current_time(m_atime);
        m_mtime = m_atime;
        m_ctime = m_atime;
        m_birthtime = m_atime;
    }
    else
    {
        memset(&m_atime, 0, sizeof(m_atime));
        memset(&m_mtime, 0, sizeof(m_mtime));
        memset(&m_ctime, 0, sizeof(m_ctime));
        memset(&m_birthtime, 0, sizeof(m_birthtime));
    }
}

FileBase::FileBase(std::shared_ptr<FileStream> data_stream,
                   std::shared_ptr<FileStream> meta_stream,
                   const key_type& key_,
                   const id_type& id_,
                   bool check,
                   unsigned block_size,
                   unsigned iv_size,
                   unsigned max_padding_size,
                   bool store_time)
    : m_header()
    , m_id(id_)
    , m_data_stream(data_stream)
    , m_meta_stream(meta_stream)
    , m_dirty(false)
    , m_check(check)
    , m_store_time(store_time)
    , m_stream()
{
    warn_if_key_not_random(key_, __FILE__, __LINE__);
    key_type data_key, meta_key;
    byte generated_keys[KEY_LENGTH * 4] = {};
    hkdf(key_.data(),
         key_.size(),
         nullptr,
         0,
         id_.data(),
         id_.size(),
         generated_keys,
         max_padding_size > 0 ? 4 * KEY_LENGTH : 3 * KEY_LENGTH);
    memcpy(data_key.data(), generated_keys, KEY_LENGTH);
    memcpy(meta_key.data(), generated_keys + KEY_LENGTH, KEY_LENGTH);
    auto crypt = make_cryptstream_aes_gcm(std::static_pointer_cast<StreamBase>(data_stream),
                                          std::static_pointer_cast<StreamBase>(meta_stream),
                                          data_key,
                                          meta_key,
                                          id_,
                                          check,
                                          block_size,
                                          iv_size,
                                          store_time ? EXTENDED_HEADER_SIZE : HEADER_SIZE);
    // The header size when time extension is enabled is enlarged by the space required by st_atime,
    // st_ctime and st_mtime

    m_stream = crypt.first;
    m_header = crypt.second;
    read_header();

    const byte null_iv[12] = {};
    m_xattr_enc.SetKeyWithIV(
        generated_keys + 2 * KEY_LENGTH, KEY_LENGTH, null_iv, array_length(null_iv));
    m_xattr_dec.SetKeyWithIV(
        generated_keys + 2 * KEY_LENGTH, KEY_LENGTH, null_iv, array_length(null_iv));

    if (!is_apple())
    {
        m_xattr_name_cryptor.emplace(generated_keys + 2 * KEY_LENGTH, KEY_LENGTH);
    }
    if (max_padding_size > 0)
    {
        warn_if_key_not_random(generated_keys, sizeof(generated_keys), __FILE__, __LINE__);
        CryptoPP::Integer integer(generated_keys + 3 * KEY_LENGTH,
                                  KEY_LENGTH,
                                  CryptoPP::Integer::UNSIGNED,
                                  CryptoPP::BIG_ENDIAN_ORDER);
        auto padding_size = static_cast<unsigned>(integer.Modulo(max_padding_size + 1));
        m_stream = std::make_shared<PaddedStream>(std::move(m_stream), padding_size);
    }
}

void FileBase::read_header()
{
    for (auto& f : m_flags)
    {
        f.store(-1);
    }
    size_t header_size = m_store_time ? EXTENDED_HEADER_SIZE : HEADER_SIZE;
    auto header = make_unique_array<byte>(header_size);
    auto rc = m_header->read_header(header.get(), header_size);
    if (!rc)
    {
        set_num_free_page(0);
    }
    else
    {
        for (size_t i = 0; i < NUM_FLAGS; ++i)
        {
            m_flags[i] = from_little_endian<uint32_t>(&header[i * sizeof(uint32_t)]);
        }
        if (m_store_time)
        {
            m_atime.tv_sec = from_little_endian<uint64_t>(&header[ATIME_OFFSET]);
            m_atime.tv_nsec
                = from_little_endian<uint32_t>(&header[ATIME_OFFSET + sizeof(uint64_t)]);
            m_mtime.tv_sec = from_little_endian<uint64_t>(&header[MTIME_OFFSET]);
            m_mtime.tv_nsec
                = from_little_endian<uint32_t>(&header[MTIME_OFFSET + sizeof(uint64_t)]);
            m_ctime.tv_sec = from_little_endian<uint64_t>(&header[CTIME_OFFSET]);
            m_ctime.tv_nsec
                = from_little_endian<uint32_t>(&header[CTIME_OFFSET + sizeof(uint64_t)]);
            m_birthtime.tv_sec = from_little_endian<uint64_t>(&header[BTIME_OFFSET]);
            m_birthtime.tv_nsec
                = from_little_endian<uint32_t>(&header[BTIME_OFFSET + sizeof(uint64_t)]);
        }
    }
}

int FileBase::get_real_type() { return type_for_mode(get_mode() & S_IFMT); }

void FileBase::stat(fuse_stat* st)
{
    m_data_stream->fstat(st);
    st->st_ino = to_inode_number(get_id());
    st->st_uid = get_uid();
    st->st_gid = get_gid();
    st->st_nlink = get_nlink();
    st->st_mode = get_mode();
    st->st_size = m_stream->size();
    auto blk_sz = m_stream->optimal_block_size();
    if (blk_sz > 1 && blk_sz < std::numeric_limits<decltype(st->st_blksize)>::max())
    {
        st->st_blksize = static_cast<decltype(st->st_blksize)>(blk_sz);
    }
    if (m_store_time)
    {
        set_atim(*st, get_atime());
        set_mtim(*st, get_mtime());
        set_ctim(*st, get_ctime());
        set_birthtim(*st, get_birthtime());
    }
}

FileBase::~FileBase() {}

void FileBase::flush()
{
    this->subflush();
    if (m_dirty)
    {
        size_t header_size = m_store_time ? EXTENDED_HEADER_SIZE : HEADER_SIZE;
        auto header = make_unique_array<byte>(header_size);
        memset(header.get(), 0, header_size);
        for (size_t i = 0; i < NUM_FLAGS; ++i)
        {
            to_little_endian<uint32_t>(m_flags[i], &header[i * sizeof(uint32_t)]);
        }
        if (m_store_time)
        {
            to_little_endian<uint64_t>(m_atime.tv_sec, &header[ATIME_OFFSET]);
            to_little_endian<uint32_t>(m_atime.tv_nsec, &header[ATIME_OFFSET + sizeof(uint64_t)]);
            to_little_endian<uint64_t>(m_mtime.tv_sec, &header[MTIME_OFFSET]);
            to_little_endian<uint32_t>(m_mtime.tv_nsec, &header[MTIME_OFFSET + sizeof(uint64_t)]);
            to_little_endian<uint64_t>(m_ctime.tv_sec, &header[CTIME_OFFSET]);
            to_little_endian<uint32_t>(m_ctime.tv_nsec, &header[CTIME_OFFSET + sizeof(uint64_t)]);
            to_little_endian<uint64_t>(m_birthtime.tv_sec, &header[BTIME_OFFSET]);
            to_little_endian<uint32_t>(m_birthtime.tv_nsec,
                                       &header[BTIME_OFFSET + sizeof(uint64_t)]);
        }
        m_header->write_header(header.get(), header_size);
        m_dirty = false;
    }
    m_header->flush_header();
    m_stream->flush();
}

void FileBase::throw_invalid_cast(int to_type)
{
    throw InvalidCastException(type_name(this->type()), type_name(to_type));
}

// The IV size is for historical reasons. Doesn't really matter.
static const ssize_t XATTR_IV_LENGTH = 16, XATTR_MAC_LENGTH = 16;

ssize_t FileBase::listxattr(char* buffer, size_t size)
{
    if (m_xattr_name_cryptor)
    {
        return generic_xattr::wrapped_listxattr(
            [m_data_stream = this->m_data_stream](char* buffer, size_t size)
            { return m_data_stream->listxattr(buffer, size); },
            *m_xattr_name_cryptor,
            buffer,
            size);
    }
    return m_data_stream->listxattr(buffer, size);
}

ssize_t FileBase::getxattr(const char* name, char* value, size_t size)
{
    if (!name)
        throwVFSException(EFAULT);
    std::string wrapped_name = m_xattr_name_cryptor
        ? generic_xattr::encrypt_xattr_name(*m_xattr_name_cryptor, name)
        : name;

    auto true_size = m_data_stream->getxattr(wrapped_name.c_str(), value, size);
    if (!value)
        return true_size;

    byte meta[XATTR_IV_LENGTH + XATTR_MAC_LENGTH];
    if (m_meta_stream->getxattr(wrapped_name.c_str(), meta, array_length(meta))
        != array_length(meta))
        throwVFSException(EIO);

    auto name_len = wrapped_name.size();
    auto header = make_unique_array<byte>(name_len + ID_LENGTH);
    memcpy(header.get(), get_id().data(), ID_LENGTH);
    memcpy(header.get() + ID_LENGTH, wrapped_name.c_str(), wrapped_name.size());

    byte* iv = meta;
    byte* mac = meta + XATTR_IV_LENGTH;
    byte* ciphertext = reinterpret_cast<byte*>(value);

    bool success = m_xattr_dec.DecryptAndVerify(reinterpret_cast<byte*>(value),
                                                mac,
                                                XATTR_MAC_LENGTH,
                                                iv,
                                                XATTR_IV_LENGTH,
                                                header.get(),
                                                name_len + ID_LENGTH,
                                                ciphertext,
                                                static_cast<size_t>(true_size));
    if (m_check && !success)
        throw XattrVerificationException(get_id(), name);
    return true_size;
}

void FileBase::utimens(const fuse_timespec* ts)
{
    if (m_store_time)
    {
        fuse_timespec current_time;

        if (ts)
        {
            set_atime(ts[0]);
            set_mtime(ts[1]);
        }
        else
        {
            set_atime(current_time);
            set_mtime(current_time);
        }

        set_ctime(current_time);
    }
    else
    {
        m_data_stream->utimens(ts);
    }
}

void FileBase::setxattr(const char* name, const char* value, size_t size, int flags)
{
    if (!name || !value)
        throwVFSException(EFAULT);

    std::string wrapped_name = m_xattr_name_cryptor
        ? generic_xattr::encrypt_xattr_name(*m_xattr_name_cryptor, name)
        : name;

    auto buffer = make_unique_array<byte>(size);
    byte* ciphertext = buffer.get();

    byte meta[XATTR_MAC_LENGTH + XATTR_IV_LENGTH];
    byte* iv = meta;
    byte* mac = iv + XATTR_IV_LENGTH;
    generate_random(iv, XATTR_IV_LENGTH);

    auto name_len = wrapped_name.size();
    auto header = make_unique_array<byte>(name_len + ID_LENGTH);
    memcpy(header.get(), get_id().data(), ID_LENGTH);
    memcpy(header.get() + ID_LENGTH, wrapped_name.c_str(), name_len);

    m_xattr_enc.EncryptAndAuthenticate(ciphertext,
                                       mac,
                                       XATTR_MAC_LENGTH,
                                       iv,
                                       XATTR_IV_LENGTH,
                                       header.get(),
                                       name_len + ID_LENGTH,
                                       reinterpret_cast<const byte*>(value),
                                       size);

    m_data_stream->setxattr(wrapped_name.c_str(), ciphertext, size, flags);
    m_meta_stream->setxattr(wrapped_name.c_str(), meta, array_length(meta), flags);
}

void FileBase::removexattr(const char* name)
{
    std::string wrapped_name = m_xattr_name_cryptor
        ? generic_xattr::encrypt_xattr_name(*m_xattr_name_cryptor, name)
        : name;

    m_data_stream->removexattr(wrapped_name.c_str());
    m_meta_stream->removexattr(wrapped_name.c_str());
}

void SimpleDirectory::initialize()
{
    char buffer[Directory::MAX_FILENAME_LENGTH + 1 + 32 + 4];
    offset_type off = 0;
    std::string name;
    std::pair<id_type, int> value;
    while (true)
    {
        auto rv = this->m_stream->read(buffer, off, array_length(buffer));
        if (rv < array_length(buffer))
            break;
        buffer[MAX_FILENAME_LENGTH] = 0;    // Set the null terminator in case the data is corrupted
        name = buffer;
        memcpy(value.first.data(), buffer + Directory::MAX_FILENAME_LENGTH + 1, ID_LENGTH);
        value.second
            = from_little_endian<uint32_t>(buffer + array_length(buffer) - sizeof(uint32_t));
        m_table.emplace(std::move(name), std::move(value));
        off += array_length(buffer);
    }
}

std::optional<std::string_view>
SimpleDirectory::get_entry_impl(std::string_view name, id_type& id, int& type)
{
    auto it = m_table.find(name);
    if (it == m_table.end())
        return {};
    memcpy(id.data(), it->second.first.data(), id.size());
    type = it->second.second;
    return it->first;
}

bool SimpleDirectory::add_entry_impl(std::string_view name, const id_type& id, int type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throwVFSException(ENAMETOOLONG);
    auto rv = m_table.emplace(name, std::make_pair(id, type));
    if (rv.second)
        m_dirty = true;
    return rv.second;
}

bool SimpleDirectory::remove_entry_impl(std::string_view name, id_type& id, int& type)
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
                             buffer + array_length(buffer) - sizeof(uint32_t));
            this->m_stream->write(buffer, off, array_length(buffer));
            off += array_length(buffer);
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
}    // namespace securefs
