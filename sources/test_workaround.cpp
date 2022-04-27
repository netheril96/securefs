#include "test_workaround.h"

#include <fuse/fuse.h>

#include <cstdlib>

namespace securefs
{

TestWorkaround::TestWorkaround()
{
    const char* env_var = std::getenv("SECUREF_TEST_WORKAROUND_SPECIAL_ATIME");
    if (!env_var)
    {
        m_special_atime = -1;
    }
    else
    {
        m_special_atime = std::strtoll(env_var, nullptr, 0);
    }
}

const TestWorkaround& TestWorkaround::instance() noexcept
{
    static const TestWorkaround tw;
    return tw;
}

void TestWorkaround::postprocess_getattr(const char* path, struct fuse_stat* st) const noexcept
{
    if (m_special_atime < 0)
    {
        return;
    }
    if (path && strcmp(path, "/") == 0)
    {
        auto& atim =
#ifdef __APPLE__
            st->st_atimespec;
#else
            st->st_atim;
#endif
        atim.tv_nsec = 0;
        atim.tv_sec = m_special_atime;
    }
}

bool TestWorkaround::preprocess_utimens(const char* path,
                                        const struct fuse_timespec ts[2]) const noexcept
{
    if (m_special_atime < 0)
    {
        return false;
    }
    if (path && strcmp(path, "/") == 0 && ts && ts[0].tv_nsec == 0
        && ts[0].tv_sec == m_special_atime)
    {
        fuse_exit(fuse_get_context()->fuse);
        return true;
    }
    return false;
}

}    // namespace securefs
