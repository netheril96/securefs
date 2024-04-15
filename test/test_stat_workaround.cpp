#include "platform.h"

#ifdef st_atime
#undef st_atime
#endif

#ifdef st_mtime
#undef st_mtime
#endif

#ifdef st_ctime
#undef st_ctime
#endif

#ifdef st_birthtime
#undef st_birthtime
#endif

#include "stat_workaround.h"

#include <doctest/doctest.h>

namespace securefs
{
namespace
{
    struct Stat1
    {
        fuse_timespec st_atim;
        fuse_timespec st_mtim;
        fuse_timespec st_ctim;
    };
    struct Stat2
    {
        fuse_timespec st_atimespec;
        fuse_timespec st_mtimespec;
        fuse_timespec st_ctimespec;
        fuse_timespec st_birthtimespec;
    };
    struct Stat3
    {
        fuse_timespec st_atim;
        fuse_timespec st_mtim;
        fuse_timespec st_ctim;
        fuse_timespec st_birthtim;
    };
    TEST_CASE("Different stat structs")
    {
        Stat1 st1{};
        Stat2 st2{};
        Stat3 st3{};
        CHECK(get_atim(st1).tv_sec == get_atim(st2).tv_sec);
        CHECK(get_mtim(st1).tv_sec == get_mtim(st2).tv_sec);
        CHECK(get_ctim(st1).tv_sec == get_ctim(st2).tv_sec);
        CHECK(!get_birthtim(st1).has_value());
        CHECK(get_birthtim(st2).has_value());
        CHECK(get_birthtim(st3).has_value());
    }
}    // namespace
}    // namespace securefs
