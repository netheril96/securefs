#include "fuse_hook.h"

#include "fuse2_workaround.h"
#include "logger.h"
#include <absl/time/clock.h>

namespace securefs
{
IdleShutdownHook::IdleShutdownHook(absl::Duration timeout)
    : timeout_(timeout)
    , timer_(
          [this]()
          {
              INFO_LOG("Idling for too long (threshold: %v), shutting down...", timeout_);
              clean_exit_fuse();
          })
{
    notify_activity();
}

void IdleShutdownHook::notify_activity() { timer_.setTimePoint(absl::Now() + timeout_); }
}    // namespace securefs
