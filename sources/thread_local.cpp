#include "thread_local.h"
#include "lock_guard.h"
#include "platform.h"

namespace securefs
{

namespace
{
    struct ThreadLocalRegistry
    {
    public:
        Mutex mu;
        std::array<bool, ThreadLocalBase::kMaxIndex> taken ABSL_GUARDED_BY(mu);

        static ThreadLocalRegistry& get_registry()
        {
            static ThreadLocalRegistry instance;
            return instance;
        }

    private:
        ThreadLocalRegistry() : mu(), taken() {}
        DISABLE_COPY_MOVE(ThreadLocalRegistry)
    };

}    // namespace

std::array<std::unique_ptr<Object>, ThreadLocalBase::kMaxIndex>& ThreadLocalBase::get_local()
{
    static thread_local std::array<std::unique_ptr<Object>, kMaxIndex> locals;
    return locals;
}

ThreadLocalBase::ThreadLocalBase()
{
    auto& registry = ThreadLocalRegistry::get_registry();
    LockGuard<Mutex> lg(registry.mu);
    for (size_t i = 0; i < registry.taken.size(); ++i)
    {
        if (!registry.taken[i])
        {
            registry.taken[i] = true;
            index_ = i;
            return;
        }
    }
    throw_runtime_error("No more slots for thread locals");
}

ThreadLocalBase::~ThreadLocalBase()
{
    auto& registry = ThreadLocalRegistry::get_registry();
    LockGuard<Mutex> lg(registry.mu);
    registry.taken[index_] = false;
}

}    // namespace securefs
