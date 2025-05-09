#include "myutils.h"
#include "object.h"
#include "resettable_timer.h"

namespace securefs
{
class FuseHook : public Object
{
public:
    virtual void notify_activity() = 0;
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

}    // namespace securefs
