#include "resettable_timer.h"

#include <absl/time/clock.h>
#include <absl/time/time.h>
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <thread>

namespace securefs
{
namespace
{
    TEST_CASE("Reset timer to 1s")
    {
        std::atomic<int> atom = 1;
        ResettableTimer timer([&]() { atom.store(2); });
        timer.setTimePoint(absl::Now() + absl::Hours(360));
        timer.setTimePoint(absl::Now() + absl::Milliseconds(16));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        REQUIRE(atom.load() == 2);
    }

    TEST_CASE("Reset timer destructor not firing callback")
    {
        std::atomic<int> atom = 1;
        {
            ResettableTimer timer([&]() { atom.store(2); });
            timer.setTimePoint(absl::Now() + absl::Hours(360));
            std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }
        REQUIRE(atom.load() == 1);
    }

    TEST_CASE("Reset timer to 360h")
    {
        std::atomic<int> atom = 1;
        ResettableTimer timer([&]() { atom.store(2); });
        timer.setTimePoint(absl::Now() + absl::Seconds(1));
        timer.setTimePoint(absl::Now() + absl::Hours(360));
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        REQUIRE(atom.load() == 1);
    }
}    // namespace
}    // namespace securefs
