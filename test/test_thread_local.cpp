
#include "thread_local.h"
#include <atomic>
#include <doctest/doctest.h>
#include <memory>

namespace securefs
{
namespace
{
    struct A
    {
        int value = 1;
        static inline std::atomic<int> destroy_count = 0;

        ~A() { ++destroy_count; }
    };

    TEST_CASE("Test custom ThreadLocal")
    {
        ThreadLocal<A> a1([]() { return std::make_unique<A>(); });
        {
            ThreadLocal<A> a2(
                []()
                {
                    auto result = std::make_unique<A>();
                    result->value = 2;
                    return result;
                });
            CHECK(a1.get().value == 1);
            CHECK(a2.get().value == 2);
        }
        // Now a2 is destroyed, and a3 will take over its slot.
        ThreadLocal<A> a3(
            []()
            {
                auto result = std::make_unique<A>();
                result->value = 3;
                return result;
            });
        CHECK(a1.get().value == 1);
        CHECK(a3.get().value == 3);
        CHECK(A::destroy_count.load() == 1);
    }
}    // namespace
}    // namespace securefs
