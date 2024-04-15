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
        time_t st_atime;       /* [XSI] Time of last access */
        long st_atimensec;     /* nsec of last access */
        time_t st_mtime;       /* [XSI] Last data modification time */
        long st_mtimensec;     /* last data modification nsec */
        time_t st_ctime;       /* [XSI] Time of last status change */
        long st_ctimensec;     /* nsec of last status change */
        time_t st_birthtime;   /*  File creation time(birth)  */
        long st_birthtimensec; /* nsec of File creation time */
    };
    TEST_CASE("Different stat structs")
    {
        Stat1 st1{};
        Stat2 st2{};
        CHECK(get_atim(st1).tv_sec == get_atim(st2).tv_sec);
    }
}    // namespace
}    // namespace securefs
