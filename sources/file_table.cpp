#include "file_table.h"

#include <cryptopp/osrng.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include <fcntl.h>
#include <unistd.h>

namespace
{

const size_t FIRST_LEVEL = 1, SECOND_LEVEL = 5;

void ensure_directory(int base_fd, const char* dir_name, mode_t mode)
{
    int rc = ::mkdirat(base_fd, dir_name, mode);
    if (rc < 0 && errno != EEXIST)
        throw securefs::OSException(errno);
}

void calculate_paths(const securefs::id_type& id,
                     std::string& first_level_dir,
                     std::string& second_level_dir,
                     std::string& full_filename,
                     std::string& meta_filename)
{
    first_level_dir = securefs::hexify(id.data(), FIRST_LEVEL);
    second_level_dir = first_level_dir + '/'
        + securefs::hexify(id.data() + FIRST_LEVEL, SECOND_LEVEL);
    full_filename = second_level_dir + '/'
        + securefs::hexify(id.data() + FIRST_LEVEL + SECOND_LEVEL,
                           id.size() - FIRST_LEVEL - SECOND_LEVEL);
    meta_filename = full_filename + ".meta";
}

/**
 * Use HMAC-SHA256 to derive a per-id key from the master key.
 * Because HMAC is pseudorandom, and master key is secret,
 * the generated key should have enough entropy not to be predicted.
 */
void derive(const securefs::key_type& master_key,
            const securefs::id_type& id,
            securefs::key_type& generated_key)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac_calculator(master_key.data(), master_key.size());
    static_assert(hmac_calculator.DIGESTSIZE == securefs::KEY_LENGTH, "Unmatched digest size");
    hmac_calculator.Update(id.data(), id.size());
    hmac_calculator.Final(generated_key.data());
}
}

namespace securefs
{
FileTable::id_hash::id_hash()
{
    CryptoPP::NonblockingRng rng;
    rng.GenerateBlock(reinterpret_cast<byte*>(&m_seed), sizeof(m_seed));
}

size_t FileTable::id_hash::operator()(const id_type& id) const noexcept
{
    return from_little_endian<size_t>(id.data() + (id.size() - sizeof(size_t))) ^ m_seed;
}

FileTable::~FileTable() {}

FileBase* FileTable::open_as(const id_type& id, int type)
{
    auto it = m_opened.find(id);
    if (it != m_opened.end())
    {
        if (it->second->type() != type)
            throw OSException(FileBase::error_number_for_not(type));
        it->second->incref();
        return it->second.get();
    }
    it = m_closed.find(id);
    if (it != m_closed.end())
    {
        if (it->second->type() != type)
            throw OSException(FileBase::error_number_for_not(type));
        auto fb = it->second;
        m_opened.emplace(*it);
        m_closed.erase(it);
        return fb.get();
    }
    std::string first_level_dir, second_level_dir, filename, metaname;
    calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
    int open_flags = is_readonly() ? O_RDONLY : O_RDWR;
    int fd = ::openat(m_dir_fd, filename.c_str(), open_flags);
    if (fd < 0)
        throw OSException(errno);
    auto main_stream = std::make_shared<POSIXFileStream>(fd);
    fd = ::openat(m_dir_fd, metaname.c_str(), open_flags);
    if (fd < 0)
        throw OSException(errno);
    auto meta_stream = std::make_shared<POSIXFileStream>(fd);
    auto param = std::make_shared<SecureParam>();
    memcpy(param->id.data(), id.data(), id.size());
    derive(m_master_key, id, param->key);
    auto crypt = make_cryptstream_aes_gcm(
        std::move(main_stream), std::move(meta_stream), std::move(param), is_auth_enabled());
    auto fb = make_file_from_type(type, std::move(crypt.first), std::move(crypt.second));
    m_opened.emplace(id, fb);
    fb->setref(1);
    return fb.get();
}

FileBase* FileTable::create_as(const id_type& id, int type)
{
    if (is_readonly())
        throw OSException(EROFS);
    if (m_opened.find(id) != m_opened.end() || m_closed.find(id) != m_closed.end())
        throw OSException(EEXIST);

    std::string first_level_dir, second_level_dir, filename, metaname;
    calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
    bool file_created = false, meta_created = false;
    try
    {
        ensure_directory(m_dir_fd, first_level_dir.c_str(), 0755);
        ensure_directory(m_dir_fd, second_level_dir.c_str(), 0755);
        int fd = ::openat(m_dir_fd, filename.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
        if (fd < 0)
            throw OSException(errno);
        file_created = true;
        auto main_stream = std::make_shared<POSIXFileStream>(fd);
        fd = ::openat(m_dir_fd, metaname.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
        if (fd < 0)
            throw OSException(errno);
        meta_created = true;
        auto meta_stream = std::make_shared<POSIXFileStream>(fd);
        auto param = std::make_shared<SecureParam>();
        memcpy(param->id.data(), id.data(), id.size());
        derive(m_master_key, id, param->key);
        auto crypt = make_cryptstream_aes_gcm(
            std::move(main_stream), std::move(meta_stream), std::move(param), is_auth_enabled());
        auto fb = make_file_from_type(type, std::move(crypt.first), std::move(crypt.second));
        m_opened.emplace(id, fb);
        fb->setref(1);
        return fb.get();
    }
    catch (...)
    {
        if (file_created)
            ::unlinkat(m_dir_fd, filename.c_str(), 0);
        if (meta_created)
            ::unlinkat(m_dir_fd, metaname.c_str(), 0);
        ::unlinkat(m_dir_fd, second_level_dir.c_str(), AT_REMOVEDIR);
        ::unlinkat(m_dir_fd, first_level_dir.c_str(), AT_REMOVEDIR);
        throw;
    }
}

void FileTable::close(FileBase* fb)
{
    if (!fb)
        NULL_EXCEPT();

    auto it = m_opened.find(fb->get_id());
    if (it == m_opened.end())
        throw InvalidArgumentException("File handle not in this table");

    if (fb->decref() <= 0)
    {
        if (m_closed.size() >= MAX_NUM_CLOSED)
            eject();
        it->second->setref(
            static_cast<ptrdiff_t>(m_counter));    // Reuse the refcount field for the timestamp
        ++m_counter;    // While this may overflow, it won't affect the correctness of the
                        // algorithm, only slightly reduce performance
        m_closed.emplace(*it);
        m_opened.erase(it);
    }
}

void FileTable::eject()
{
    assert(m_closed.size() > NUM_EJECT);

    struct closure
    {
        ptrdiff_t counter;
        table_type::iterator iter;

        explicit closure(ptrdiff_t counter, table_type::iterator iter)
            : counter(counter), iter(iter)
        {
        }

        bool operator<(const closure& that) const noexcept { return counter < that.counter; }
    };

    std::vector<closure> temp;
    for (auto it = m_closed.begin(); it != m_closed.end(); ++it)
    {
        temp.emplace_back(it->second->getref(), it);
    }

    // Eject the file handles closed from the earliest time
    std::partial_sort(temp.begin(), temp.begin() + NUM_EJECT, temp.end());
    for (size_t i = 0; i < NUM_EJECT; ++i)
    {
        temp[i].iter->second->flush();
        m_closed.erase(temp[i].iter);
    }
}
}
