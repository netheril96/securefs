#include "di.h"

#include <boost/di.hpp>
#include <boost/di/extension/injections/assisted_injection.hpp>
#include <doctest/doctest.h>
#include <functional>
#include <memory>

namespace securefs
{
struct A : public Injectable
{
};

struct B
{
    BOOST_DI_INJECT(B, std::unique_ptr<A> a, (named = di::extension::assisted) int b)
        : a(std::move(a)), b(2 * b)
    {
    }

    std::unique_ptr<A> a;
    int b;
};

TEST_CASE("Assisted injection")
{
    using Bcreator = std::function<std::unique_ptr<B>(int)>;
    auto injector
        = di::make_injector(di::bind<Bcreator>().to(di::extension::assisted_injection<B>()));
    auto creator = injector.create<Bcreator>();
    CHECK(creator(3)->b == 6);
}
}    // namespace securefs
