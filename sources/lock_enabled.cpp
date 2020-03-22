#include "lock_enabled.h"
#include <atomic>

namespace securefs
{
static std::atomic_bool lock_flag{true};

bool is_lock_enabled() { return lock_flag.load(); }
void set_lock_enabled(bool value) { return lock_flag.store(value); }
}    // namespace securefs
