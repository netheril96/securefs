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
}    // namespace securefs
