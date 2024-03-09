#pragma once
#include "object.h"

#include <array>
#include <functional>
#include <memory>

namespace securefs
{

class ThreadLocalBase : public Object
{
public:
    inline static constexpr size_t kMaxIndex = 256;

protected:
    static std::array<std::unique_ptr<Object>, kMaxIndex>& get_local();

protected:
    size_t index_;

    ThreadLocalBase();
    ~ThreadLocalBase() override;
};

template <typename T>
class ThreadLocal final : public ThreadLocalBase
{
public:
    struct Holder : public Object
    {
        T value;

        template <typename... Args>
        explicit Holder(Args&&... args) : value(std::forward<Args>(args)...)
        {
        }

        ~Holder() override = default;
    };

    using Initializer = std::function<std::unique_ptr<Holder>()>;

private:
    Initializer init_;

public:
    explicit ThreadLocal(Initializer init) : init_(std::move(init)) {}

    T& get()
    {
        std::unique_ptr<Object>& ptr = get_local()[index_];
        if (auto p = dynamic_cast<Holder*>(ptr.get()); p)
        {
            return p->value;
        }
        ptr = init_();
        return dynamic_cast<Holder*>(ptr.get())->value;
    }
};
}    // namespace securefs
