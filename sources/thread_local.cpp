#include "thread_local.h"
#include "exceptions.h"
#include "lock_guard.h"
#include "platform.h"
#include <cstdint>

namespace securefs
{

namespace
{
    struct ThreadLocalRegistry
    {
    public:
        Mutex mu;
        std::array<bool, ThreadLocalBase::kMaxIndex> taken ABSL_GUARDED_BY(mu);
        int64_t generation ABSL_GUARDED_BY(mu);

        static ThreadLocalRegistry& get_registry()
        {
            static ThreadLocalRegistry instance{};
            return instance;
        }

    private:
        ThreadLocalRegistry() : mu(), taken() {}
        DISABLE_COPY_MOVE(ThreadLocalRegistry)
    };

}    // namespace

ThreadLocalBase::UnderlyingThreadLocalType& ThreadLocalBase::get_local()
{
    static thread_local ThreadLocalBase::UnderlyingThreadLocalType locals{};
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
            generation_ = ++registry.generation;
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
