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

class NoOpFuseHook final : public FuseHook
{
public:
    void notify_activity() override {}
};

class IdleShutdownHook final : public FuseHook
{
public:
    explicit IdleShutdownHook(absl::Duration timeout);
    void notify_activity() override;

private:
    absl::Duration timeout_;
    ResettableTimer timer_;
};

class MultiFuseHook final : public FuseHook
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
