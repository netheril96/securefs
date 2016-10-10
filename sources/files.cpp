#include "files.h"
#include "myutils.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

#include <cryptopp/secblock.h>

#include <sys/types.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

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
 Each time field is composed of three 32-bit integers, the first two compose the time in seconds
since epoch, and last one is the number of nanoseconds.
**/

namespace securefs
{

FileBase::FileBase(std::shared_ptr<FileStream> data_stream,
                   std::shared_ptr<FileStream> meta_stream,
                   const key_type& key_,
                   const id_type& id_,
                   bool check,
                   unsigned block_size,
                   unsigned iv_size,
                   bool store_time)
    : m_refcount(1)
    , m_header()
    , m_id(id_)
    , m_data_stream(data_stream)
    , m_meta_stream(meta_stream)
    , m_dirty(false)
    , m_check(check)
    , m_store_time(store_time)
    , m_stream()
{
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
    auto crypt = make_cryptstream_aes_gcm(std::static_pointer_cast<StreamBase>(data_stream),
                                          std::static_pointer_cast<StreamBase>(meta_stream),
                                          data_key,
                                          meta_key,
                                          id_,
                                          check,
                                          block_size,
                                          iv_size,
                                          store_time ? 64 : 32);
    // The header size when time extension is enabled is enlarged by the space required by st_atime,
    // st_ctime and st_mtime

    m_stream = crypt.first;
    m_header = crypt.second;
    read_header();
}

void FileBase::read_header()
{
    memset(m_flags, 0xFF, sizeof(m_flags));
    size_t header_size = m_store_time ? 64 : 32;
    auto header = make_unique_array<byte>(header_size);
    auto rc = m_header->read_header(header.get(), header_size);
    if (!rc)
    {
        set_num_free_page(0);
    }
    else
    {
        for (size_t i = 0; i < header_size / sizeof(uint32_t); ++i)
        {
            m_flags[i] = from_little_endian<uint32_t>(&header[i * sizeof(uint32_t)]);
        }
    }
}

void FileBase::convert_flags_to_timespec(const uint32_t flags[3], timespec& spec) noexcept
{
    spec.tv_sec = static_cast<uint64_t>(flags[0]) + (static_cast<uint64_t>(flags[1]) << 32);
    spec.tv_nsec = flags[2];
}

void FileBase::convert_timespec_to_flags(uint32_t* flags, const timespec& spec) noexcept
{
    flags[0] = static_cast<uint32_t>(spec.tv_sec);
    flags[1] = static_cast<uint32_t>(spec.tv_sec >> 32);
    flags[2] = static_cast<uint32_t>(flags[2]);
}

int FileBase::get_real_type() { return type_for_mode(get_mode() & S_IFMT); }

void FileBase::stat(FUSE_STAT* st)
{
    m_data_stream->fstat(st);

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
#ifdef __APPLE__
        get_atime(st->st_atimespec);
        get_mtime(st->st_mtimespec);
        get_ctime(st->st_ctimespec);
#else
        get_atime(st->st_atim);
        get_mtime(st->st_mtim);
        get_ctime(st->st_ctim);
#endif
    }
}

FileBase::~FileBase() {}

void FileBase::flush()
{
    this->subflush();
    if (m_dirty)
    {
        size_t header_size = m_store_time ? 64 : 32;
        auto header = make_unique_array<byte>(header_size);
        for (size_t i = 0; i < header_size / sizeof(uint32_t); ++i)
        {
            to_little_endian<uint32_t>(m_flags[i], &header[i * sizeof(uint32_t)]);
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
    return m_data_stream->listxattr(buffer, size);
}

ssize_t FileBase::getxattr(const char* name, char* value, size_t size)
{
    if (!name)
        throw OSException(EFAULT);

    auto true_size = m_data_stream->getxattr(name, value, size);
    if (!value)
        return true_size;

    byte meta[XATTR_IV_LENGTH + XATTR_MAC_LENGTH];
    if (m_meta_stream->getxattr(name, meta, sizeof(meta)) != sizeof(meta))
        throw OSException(EIO);

    auto name_len = strlen(name);
    auto header = make_unique_array<byte>(name_len + ID_LENGTH);
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

void FileBase::utimens(const struct timespec* ts)
{
    if (m_store_time)
    {
        struct timespec current_time;
#ifdef __MACH__    // OS X does not have clock_gettime, use clock_get_time
        clock_serv_t cclock;
        mach_timespec_t mts;
        host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
        clock_get_time(cclock, &mts);
        mach_port_deallocate(mach_task_self(), cclock);
        current_time.tv_sec = mts.tv_sec;
        current_time.tv_nsec = mts.tv_nsec;
#else
        clock_gettime(CLOCK_REALTIME, &current_time);
#endif

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
        throw OSException(EFAULT);

    auto buffer = make_unique_array<byte>(size);
    byte* ciphertext = buffer.get();

    byte meta[XATTR_MAC_LENGTH + XATTR_IV_LENGTH];
    byte* iv = meta;
    byte* mac = iv + XATTR_IV_LENGTH;
    generate_random(iv, XATTR_IV_LENGTH);

    auto name_len = strlen(name);
    auto header = make_unique_array<byte>(name_len + ID_LENGTH);
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

    m_data_stream->setxattr(name, ciphertext, size, flags);
    m_meta_stream->setxattr(name, meta, sizeof(meta), flags);
}

void FileBase::removexattr(const char* name)
{
    m_data_stream->removexattr(name);
    m_meta_stream->removexattr(name);
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
