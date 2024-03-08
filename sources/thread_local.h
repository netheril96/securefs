#pragma once
#include "myutils.h"

#include <any>
#include <array>

namespace securefs
{
class ThreadLocal
{
public:
    static constexpr size_t kMaxIndex = 256;

private:
    static std::array<std::any, kMaxIndex>& get_local();

    size_t index_;

public:
    ThreadLocal();
    ~ThreadLocal();

    DISABLE_COPY_MOVE(ThreadLocal)

    std::any& get() { return get_local()[index_]; }
    const std::any& get() const { return get_local()[index_]; }
};
}    // namespace securefs
