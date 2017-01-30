#include "lite_fs.h"

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
        : m_name(name)
        , m_crypt_stream(file_stream, master_key, block_size, iv_size, check)
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
}
}
