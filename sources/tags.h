#pragma once

#include <initializer_list>
#include <utility>

namespace securefs
{
struct tBlockSize
{
};
struct tIvSize
{
};
struct tMaxPaddingSize
{
};
struct tMasterKey
{
};
struct tNameMasterKey
{
};
struct tContentMasterKey
{
};
struct tXattrMasterKey
{
};
struct tPaddingMasterKey
{
};
struct tLegacy
{
};
struct tReadOnly
{
};
struct tVerify
{
};
struct tStoreTimeWithinFs
{
};
struct tLongNameThreshold
{
};
struct tCaseInsensitive
{
};
struct tEnableXattr
{
};
struct tInner
{
};
template <unsigned Layer>
struct tWrapped
{
};

template <typename T, typename Tag>
struct StrongType
{
    explicit StrongType(T val) : value(val) {}
    explicit StrongType(const std::initializer_list<T>&) = delete;
    const T& get() const { return value; }
    T& get() { return value; }

    // Arithmetic operators
    template <typename U = T>
    auto operator+(const StrongType& other) const -> decltype(std::declval<U>() + std::declval<U>(),
                                                              StrongType(std::declval<U>()))
    {
        return StrongType(value + other.value);
    }

    template <typename U = T>
    auto operator-(const StrongType& other) const -> decltype(std::declval<U>() - std::declval<U>(),
                                                              StrongType(std::declval<U>()))
    {
        return StrongType(value - other.value);
    }

    template <typename U = T>
    auto operator*(const StrongType& other) const -> decltype(std::declval<U>() * std::declval<U>(),
                                                              StrongType(std::declval<U>()))
    {
        return StrongType(value * other.value);
    }

    template <typename U = T>
    auto operator/(const StrongType& other) const -> decltype(std::declval<U>() / std::declval<U>(),
                                                              StrongType(std::declval<U>()))
    {
        return StrongType(value / other.value);
    }

    // Comparison operators
    template <typename U = T>
    auto operator<(const StrongType& other) const -> decltype(std::declval<U>() < std::declval<U>(),
                                                              bool())
    {
        return value < other.value;
    }

    template <typename U = T>
    auto operator>(const StrongType& other) const -> decltype(std::declval<U>() > std::declval<U>(),
                                                              bool())
    {
        return value > other.value;
    }

    template <typename U = T>
    auto operator==(const StrongType& other) const -> decltype(std::declval<U>()
                                                                   == std::declval<U>(),
                                                               bool())
    {
        return value == other.value;
    }

    template <typename U = T>
    auto operator<=(const StrongType& other) const -> decltype(std::declval<U>()
                                                                   <= std::declval<U>(),
                                                               bool())
    {
        return value <= other.value;
    }

    template <typename U = T>
    auto operator>=(const StrongType& other) const -> decltype(std::declval<U>()
                                                                   >= std::declval<U>(),
                                                               bool())
    {
        return value >= other.value;
    }

private:
    T value;
};
}    // namespace securefs
