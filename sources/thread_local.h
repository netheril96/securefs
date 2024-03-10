#pragma once
#include "object.h"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>

namespace securefs
{

class ThreadLocalBase : public Object
{
public:
    inline static constexpr size_t kMaxIndex = 256;

protected:
    using TypeErasedDestructor = void (*)(void*);
    struct Holder
    {
        // To distinguish reuse of a slot.
        int64_t generation = -1;
        TypeErasedDestructor destructor = nullptr;
        void* data = nullptr;

        Holder() = default;
        ~Holder()
        {
            if (data && destructor)
            {
                destructor(data);
            }
        }
    };
    using UnderlyingThreadLocalType = std::array<Holder, kMaxIndex>;
    static UnderlyingThreadLocalType& get_local();

protected:
    size_t index_;
    int64_t generation_;

    ThreadLocalBase();
    ~ThreadLocalBase() override;
};

template <typename T>
class ThreadLocal final : public ThreadLocalBase
{
public:
    using Initializer = std::function<std::unique_ptr<T>()>;

private:
    Initializer init_;

public:
    explicit ThreadLocal(Initializer init) : init_(std::move(init)) {}

    T& get()
    {
        Holder& holder = get_local()[index_];
        if (!holder.data || holder.generation != this->generation_)
        {
            // Either the current slot hasn't been initialized, or it was left over by a previous
            // released `ThreadLocal<>` object.

            if (holder.data && holder.destructor)
                holder.destructor(holder.data);

            // Because `init()` may throw, we need to set the state of `holder` properly before
            // calling `init`.
            holder.data = nullptr;
            holder.destructor = [](void* p) { delete static_cast<T*>(p); };
            holder.generation = this->generation_;

            holder.data = init_().release();
        }
        return *static_cast<T*>(holder.data);
    }
};
}    // namespace securefs
