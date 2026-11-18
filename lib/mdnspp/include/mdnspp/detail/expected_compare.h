#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_COMPARE_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_COMPARE_H

#include "mdnspp/detail/expected_traits.h"

#include <utility>
#include <concepts>
#include <type_traits>

namespace mdnspp::detail {

template <typename T1, typename E1, typename T2, typename E2>
    requires(std::is_void_v<T1> == std::is_void_v<T2>)
constexpr bool operator==(const expected<T1, E1> &x, const expected<T2, E2> &y)
{
    if(x.has_value() != y.has_value())
        return false;
    if(!x.has_value())
        return static_cast<bool>(x.error() == y.error());
    if constexpr(std::is_void_v<T1>)
        return true;
    else
        return static_cast<bool>(*x == *y);
}

template <typename T1, typename E1, typename T2>
    requires(!is_expected_v<T2> && !std::is_void_v<T1> &&
             requires(const T1 &a, const T2 &b) {
                 { a == b } -> std::convertible_to<bool>;
             })
constexpr bool operator==(const expected<T1, E1> &x, const T2 &v)
{
    return x.has_value() && static_cast<bool>(*x == v);
}

template <typename T1, typename E1, typename E2>
constexpr bool operator==(const expected<T1, E1> &x, const unexpected<E2> &e)
{
    return !x.has_value() && static_cast<bool>(x.error() == e.error());
}

}

#endif
