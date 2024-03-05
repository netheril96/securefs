#pragma once

namespace securefs
{
class Object
{
public:
    Object() = default;
    virtual ~Object() = default;

    Object(Object&&) = delete;
    Object& operator=(Object&&) = delete;
};
}    // namespace securefs
