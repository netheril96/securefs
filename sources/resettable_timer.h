#pragma once

#include "myutils.h"

#include <absl/synchronization/mutex.h>
#include <absl/time/time.h>

#include <functional>
#include <thread>

namespace securefs
{
class ResettableTimer
{
public:
    // Note: the `callback` must be thread safe, that is, it can be called any time on any thread.
    explicit ResettableTimer(std::function<void()> callback) : callback_(std::move(callback)) {}
    ~ResettableTimer();
    void setTimePoint(absl::Time trigger_time);

    DISABLE_COPY_MOVE(ResettableTimer);

private:
    absl::Mutex mu_;
    std::function<void()> callback_;
    absl::Time trigger_time_ ABSL_GUARDED_BY(mu_) = absl::UniversalEpoch();
    bool should_wake_up_ ABSL_GUARDED_BY(mu_) = false;
    bool is_exiting_ ABSL_GUARDED_BY(mu_) = false;
    std::thread work_thread_ ABSL_GUARDED_BY(mu_);
};
}    // namespace securefs
