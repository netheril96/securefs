#pragma once

#include <utility>

#include <Windows.h>

namespace securefs
{
class UniqueHandle
{
private:
    HANDLE m_handle;

public:
    explicit UniqueHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : m_handle(handle) {}

    ~UniqueHandle()
    {
        if (m_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_handle);
        }
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : m_handle(other.m_handle)
    {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other)
        {
            swap(other);
        }
        return *this;
    }

    HANDLE get() const noexcept { return m_handle; }

    HANDLE release() noexcept
    {
        HANDLE old_handle = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return old_handle;
    }

    void reset(HANDLE new_handle = INVALID_HANDLE_VALUE) noexcept
    {
        if (m_handle != new_handle)
        {
            if (m_handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(m_handle);
            }
            m_handle = new_handle;
        }
    }

    void swap(UniqueHandle& other) noexcept { std::swap(m_handle, other.m_handle); }

    explicit operator bool() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }
};

inline void swap(UniqueHandle& a, UniqueHandle& b) noexcept { a.swap(b); }

}    // namespace securefs
