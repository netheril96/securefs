#pragma once
#include <absl/base/thread_annotations.h>
#include <absl/synchronization/mutex.h>

namespace securefs
{
template <class Lockable>
class ABSL_SCOPED_LOCKABLE LockGuard
{
private:
    Lockable* m_lock;

public:
    explicit LockGuard(Lockable& lock, bool exclusive) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock)
        : m_lock(&lock)
    {
        lock.lock(exclusive);
    }
    explicit LockGuard(Lockable& lock) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock) : m_lock(&lock)
    {
        lock.lock();
    }
    ~LockGuard() ABSL_UNLOCK_FUNCTION() { m_lock->unlock(); }
    LockGuard(LockGuard&&) = delete;
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(LockGuard&&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};

template <>
class ABSL_SCOPED_LOCKABLE LockGuard<absl::Mutex>
{
public:
    using Lockable = absl::Mutex;

private:
    Lockable* m_lock;

public:
    explicit LockGuard(Lockable& lock, bool exclusive) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock)
        : m_lock(&lock)
    {
        if (exclusive)
        {
            m_lock->Lock();
        }
        else
        {
            m_lock->ReaderLock();
        }
    }
    explicit LockGuard(Lockable& lock) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock) : m_lock(&lock)
    {
        m_lock->Lock();
    }
    ~LockGuard() ABSL_UNLOCK_FUNCTION() { m_lock->Unlock(); }
    LockGuard(LockGuard&&) = delete;
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(LockGuard&&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};

template <class Lockable>
class ABSL_SCOPED_LOCKABLE UniqueLock
{
private:
    Lockable* m_lock;
    bool m_owns_lock;

public:
    explicit UniqueLock(Lockable& lock) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock)
        : m_lock(&lock), m_owns_lock(true)
    {
        m_lock->lock();
    }

    UniqueLock(Lockable& lock, std::defer_lock_t) noexcept : m_lock(&lock), m_owns_lock(false) {}

    UniqueLock(Lockable& lock, std::try_to_lock_t) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock)
        : m_lock(&lock), m_owns_lock(m_lock->try_lock())
    {
    }

    ~UniqueLock() ABSL_UNLOCK_FUNCTION()
    {
        if (m_owns_lock)
        {
            m_lock->unlock();
        }
    }

    void lock() ABSL_EXCLUSIVE_LOCK_FUNCTION()
    {
        if (!m_owns_lock)
        {
            m_lock->lock();
            m_owns_lock = true;
        }
    }

    bool try_lock() ABSL_EXCLUSIVE_LOCK_FUNCTION()
    {
        if (!m_owns_lock)
        {
            m_owns_lock = m_lock->try_lock();
        }
        return m_owns_lock;
    }

    void unlock() ABSL_UNLOCK_FUNCTION()
    {
        if (m_owns_lock)
        {
            m_lock->unlock();
            m_owns_lock = false;
        }
    }

    bool owns_lock() const noexcept { return m_owns_lock; }

    Lockable* release() noexcept
    {
        Lockable* temp = m_lock;
        m_lock = nullptr;
        m_owns_lock = false;
        return temp;
    }

    Lockable* mutex() const noexcept { return m_lock; }

    UniqueLock(UniqueLock&&) = delete;
    UniqueLock(const UniqueLock&) = delete;
    UniqueLock& operator=(UniqueLock&&) = delete;
    UniqueLock& operator=(const UniqueLock&) = delete;
};

template <>
class ABSL_SCOPED_LOCKABLE UniqueLock<absl::Mutex>
{
public:
    using Lockable = absl::Mutex;

private:
    Lockable* m_lock;
    bool m_owns_lock;

public:
    explicit UniqueLock(Lockable& lock) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock)
        : m_lock(&lock), m_owns_lock(true)
    {
        m_lock->Lock();
    }

    UniqueLock(Lockable& lock, std::defer_lock_t) noexcept : m_lock(&lock), m_owns_lock(false) {}

    UniqueLock(Lockable& lock, std::try_to_lock_t) ABSL_EXCLUSIVE_LOCK_FUNCTION(&lock)
        : m_lock(&lock), m_owns_lock(m_lock->TryLock())
    {
    }

    ~UniqueLock() ABSL_UNLOCK_FUNCTION()
    {
        if (m_owns_lock)
        {
            m_lock->Unlock();
        }
    }

    void lock() ABSL_EXCLUSIVE_LOCK_FUNCTION()
    {
        if (!m_owns_lock)
        {
            m_lock->Lock();
            m_owns_lock = true;
        }
    }

    bool try_lock() ABSL_EXCLUSIVE_LOCK_FUNCTION()
    {
        if (!m_owns_lock)
        {
            m_owns_lock = m_lock->TryLock();
        }
        return m_owns_lock;
    }

    void unlock() ABSL_UNLOCK_FUNCTION()
    {
        if (m_owns_lock)
        {
            m_lock->Unlock();
            m_owns_lock = false;
        }
    }

    bool owns_lock() const noexcept { return m_owns_lock; }

    Lockable* release() noexcept
    {
        Lockable* temp = m_lock;
        m_lock = nullptr;
        m_owns_lock = false;
        return temp;
    }

    Lockable* mutex() const noexcept { return m_lock; }

    UniqueLock(UniqueLock&&) = delete;
    UniqueLock(const UniqueLock&) = delete;
    UniqueLock& operator=(UniqueLock&&) = delete;
    UniqueLock& operator=(const UniqueLock&) = delete;
};
}    // namespace securefs
