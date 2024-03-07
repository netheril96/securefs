#pragma once

#include <type_traits>
namespace securefs
{
struct DefaultDiPolicy;
}
#define BOOST_DI_CFG ::securefs::DefaultDiPolicy

#include <boost/di.hpp>

namespace securefs
{
namespace di = boost::di;

struct Injectable
{
};

struct DefaultDiPolicy : public di::config
{
public:
    static auto policies(...) noexcept
    {
        using namespace di::policies;
        using namespace di::policies::operators;
        return di::make_policies(
            [](auto arg_wrapper)
            {
                using impl = typename decltype(arg_wrapper)::given;
                using scope = typename decltype(arg_wrapper)::scope;
                using arity = typename decltype(arg_wrapper)::arity;
                static_assert(std::is_same<di::_, impl>::value || arity::value > 0
                                  || std::is_same<scope, di::scopes::instance>::value
                                  || std::is_base_of<Injectable, impl>::value,
                              "Only explicit bound or constructible or Injectable subclasses can "
                              "be injected");
            });
    }
};
}    // namespace securefs
