#include "resettable_timer.h"
#include <absl/base/thread_annotations.h>
#include <absl/synchronization/mutex.h>
#include <absl/time/clock.h>
#include <thread>

namespace securefs
{

ResettableTimer::~ResettableTimer()
{
    {
        absl::MutexLock ml(&mu_);
        is_exiting_ = true;
    }
    if (work_thread_.joinable())
    {
        work_thread_.join();
    }
}

void ResettableTimer::setTimePoint(absl::Time trigger_time)
{
    absl::MutexLock ml(&mu_);
    // If the new time point is in the future, then we can just let the work thread wake up
    // naturally.
    should_wake_up_ = trigger_time < this->trigger_time_;
    this->trigger_time_ = trigger_time;

    if (!work_thread_.joinable())
    {
        work_thread_ = std::thread(
            [this]()
            {
                while (true)
                {
                    absl::MutexLock ml(&mu_);
                    mu_.AwaitWithDeadline(absl::Condition(
                                              +[](const ResettableTimer* t)
                                                   ABSL_EXCLUSIVE_LOCKS_REQUIRED(t->mu_)
                                              { return t->should_wake_up_ || t->is_exiting_; },
                                              this),
                                          this->trigger_time_);
                    if (is_exiting_)
                    {
                        return;
                    }
                    should_wake_up_ = false;
                    auto now = absl::Now();
                    if (now >= this->trigger_time_)
                    {
                        break;
                    }
                }
                callback_();
            });
    }
}

}    // namespace securefs
