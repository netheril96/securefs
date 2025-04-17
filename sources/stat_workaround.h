#pragma once

#include "platform.h"

#include <cstddef>
#include <optional>

namespace securefs
{
#define GENERATE_TIME_HELPER(PREFIX)                                                               \
    template <typename Stat>                                                                       \
    constexpr inline auto has_##PREFIX##tim(std::nullptr_t)                                        \
        ->decltype(std::declval<Stat>().st_##PREFIX##tim, true)                                    \
    {                                                                                              \
        return true;                                                                               \
    }                                                                                              \
                                                                                                   \
    template <typename Stat>                                                                       \
    constexpr inline auto has_##PREFIX##tim(...)                                                   \
    {                                                                                              \
        return false;                                                                              \
    }                                                                                              \
                                                                                                   \
    template <typename Stat>                                                                       \
    inline fuse_timespec get_##PREFIX##tim(const Stat& st)                                         \
    {                                                                                              \
        if constexpr (has_##PREFIX##tim<Stat>(nullptr))                                            \
        {                                                                                          \
            return st.st_##PREFIX##tim;                                                            \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            return st.st_##PREFIX##timespec;                                                       \
        }                                                                                          \
    }                                                                                              \
                                                                                                   \
    template <typename Stat>                                                                       \
    inline void set_##PREFIX##tim(Stat& st, const fuse_timespec& value)                            \
    {                                                                                              \
        if constexpr (has_##PREFIX##tim<Stat>(nullptr))                                            \
        {                                                                                          \
            st.st_##PREFIX##tim = value;                                                           \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            st.st_##PREFIX##timespec = value;                                                      \
        }                                                                                          \
    }

GENERATE_TIME_HELPER(a)
GENERATE_TIME_HELPER(m)
GENERATE_TIME_HELPER(c)

#undef GENERATE_TIME_HELPER

template <typename Stat>
constexpr inline auto has_birthtim(std::nullptr_t) -> decltype(std::declval<Stat>().st_birthtim,
                                                               true)
{
    return true;
}

template <typename Stat>
constexpr inline auto has_birthtim(...)
{
    return false;
}

template <typename Stat>
constexpr inline auto
has_birthtimespec(std::nullptr_t) -> decltype(std::declval<Stat>().st_birthtimespec, true)
{
    return true;
}

template <typename Stat>
constexpr inline auto has_birthtimespec(...)
{
    return false;
}

template <typename Stat>
inline std::optional<fuse_timespec> get_birthtim(const Stat& st)
{
    if constexpr (has_birthtim<Stat>(nullptr))
    {
        return st.st_birthtim;
    }
    else if constexpr (has_birthtimespec<Stat>(nullptr))
    {
        return st.st_birthtimespec;
    }
    else
    {
        return std::nullopt;
    }
}

template <typename Stat>
inline void set_birthtim(Stat& st, const fuse_timespec& value)
{
    if constexpr (has_birthtim<Stat>(nullptr))
    {
        st.st_birthtim = value;
    }
    else if constexpr (has_birthtimespec<Stat>(nullptr))
    {
        st.st_birthtimespec = value;
    }
    else
    {
        // No op
    }
}
}    // namespace securefs
