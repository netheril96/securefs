#pragma once
#include "platform.h"

namespace securefs
{
// FUSE mounting and unmounting are inherently racy. The time window is too small for human users to
// notice, but too much for automated tests.
class TestWorkaround
{
private:
    TestWorkaround();

private:
    long long m_special_atime;

public:
    static const TestWorkaround& instance() noexcept;

    void postprocess_getattr(const char* path, struct fuse_stat* st) const noexcept;
    bool preprocess_utimens(const char* path, const struct fuse_timespec ts[2]) const noexcept;
};
}    // namespace securefs
