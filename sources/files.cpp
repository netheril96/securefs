#include "files.h"

namespace securefs
{
void Filebase::read_header()
{
    byte header[sizeof(m_mode) + sizeof(m_uid) + sizeof(m_gid) + sizeof(m_root_page)
                + sizeof(m_start_free_page) + sizeof(m_num_free_page)];
    auto rc = m_header->read_header(header, sizeof(header));
    if (!rc)
    {
        m_mode = 0;
        m_uid = 0;
        m_gid = 0;
        m_root_page = 0;
        m_start_free_page = 0;
        m_num_free_page = 0;
    }
    else
    {
        const byte* ptr = header;
        m_mode = from_little_endian<decltype(m_mode)>(ptr);
        ptr += sizeof(m_mode);
        m_uid = from_little_endian<decltype(m_uid)>(ptr);
        ptr += sizeof(m_uid);
        m_gid = from_little_endian<decltype(m_gid)>(ptr);
        ptr += sizeof(m_gid);
        m_root_page = from_little_endian<decltype(m_root_page)>(ptr);
        ptr += sizeof(m_root_page);
        m_start_free_page = from_little_endian<decltype(m_start_free_page)>(ptr);
        ptr += sizeof(m_start_free_page);
        m_num_free_page = from_little_endian<decltype(m_num_free_page)>(ptr);
        ptr += sizeof(m_num_free_page);
    }
}
}
