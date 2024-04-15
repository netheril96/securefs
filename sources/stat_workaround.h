#pragma once

#include "platform.h"
#include <type_traits>

namespace securefs
{
template <typename Stat>
constexpr inline auto has_atim(const Stat& st) -> decltype(st.st_atim, true)
{
    return true;
}

constexpr inline auto has_atim(...) { return false; }

template <typename Stat>
inline fuse_timespec get_atim(const Stat& st)
{
    if constexpr (has_atim(st))
    {
        return st.st_atim;
    }
    else
    {
        return {st.st_atime, st.st_atimensec};
    }
}
}    // namespace securefs
