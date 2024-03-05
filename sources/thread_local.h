#pragma once
#include "myutils.h"

#include <absl/types/any.h>

#include <array>
#include <functional>

namespace securefs
{
class ThreadLocal
{
public:
    static constexpr size_t kMaxIndex = 256;

private:
    static std::array<absl::any, kMaxIndex>& get_local();

    size_t index_;

public:
    ThreadLocal();
    ~ThreadLocal();

    DISABLE_COPY_MOVE(ThreadLocal)

    absl::any& get() { return get_local()[index_]; }
    const absl::any& get() const { return get_local()[index_]; }
};
}    // namespace securefs
