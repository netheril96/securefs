#pragma once
#include "thread_safety_annotations.hpp"

namespace securefs
{
template <class Lockable>
class THREAD_ANNOTATION_SCOPED_CAPABILITY LockGuard
{
private:
    Lockable* m_lock;

public:
    explicit LockGuard(Lockable& lock, bool exclusive) THREAD_ANNOTATION_ACQUIRE(lock)
        : m_lock(&lock)
    {
        lock.lock(exclusive);
    }
    explicit LockGuard(Lockable& lock) THREAD_ANNOTATION_ACQUIRE(lock) : m_lock(&lock)
    {
        lock.lock();
    }
    ~LockGuard() THREAD_ANNOTATION_RELEASE() { m_lock->unlock(); }
    LockGuard(LockGuard&&) = delete;
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(LockGuard&&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};
}    // namespace securefs
