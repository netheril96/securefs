#pragma once

#include "object.h"
#include "resettable_timer.h"

#include <memory>

namespace securefs
{
class FuseHook : public Object
{
public:
    virtual void notify_activity() = 0;
};

class NoOpFuseHook : public FuseHook
{
public:
    void notify_activity() override {}
};

class IdleShutdownHook : public FuseHook
{
public:
    explicit IdleShutdownHook(absl::Duration timeout);
    void notify_activity() override;

private:
    ResettableTimer timer_;
    absl::Duration timeout_;
};

class MultiFuseHook : public FuseHook
{
public:
    void add_hook(std::shared_ptr<FuseHook> hook) { hooks_.push_back(std::move(hook)); }
    void notify_activity() override
    {
        for (auto& hook : hooks_)
        {
            hook->notify_activity();
        }
    }

private:
    std::vector<std::shared_ptr<FuseHook>> hooks_;
};

}    // namespace securefs
