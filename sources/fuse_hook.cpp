#include "fuse_hook.h"

#include "fuse2_workaround.h"
#include <absl/time/clock.h>

namespace securefs
{
IdleShutdownHook::IdleShutdownHook(absl::Duration timeout)
    : timer_(&clean_exit_fuse), timeout_(timeout)
{
    timer_.setTimePoint(absl::Now() + timeout);
}

void IdleShutdownHook::notify_activity() { timer_.setTimePoint(absl::Now() + timeout_); }
}    // namespace securefs
