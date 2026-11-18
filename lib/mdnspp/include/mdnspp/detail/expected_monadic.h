#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_MONADIC_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_MONADIC_H

#include "mdnspp/detail/unexpected.h"
#include "mdnspp/detail/expected_traits.h"

#include <utility>
#include <functional>
#include <type_traits>

namespace mdnspp::detail::monadic {

template <typename Self>
inline constexpr bool holds_void_v = std::is_void_v<typename std::remove_cvref_t<Self>::value_type>;

template <typename Self, typename F>
constexpr value_invoke_t<Self, F> invoke_value(Self &&self, F &&f)
{
    if constexpr(holds_void_v<Self>)
        return std::invoke(std::forward<F>(f));
    else
        return std::invoke(std::forward<F>(f), *std::forward<Self>(self));
}

template <typename R, typename Self>
constexpr R from_value(Self &&self)
{
    if constexpr(holds_void_v<Self>)
        return R();
    else
        return R(std::in_place, *std::forward<Self>(self));
}

template <typename Self, typename F>
constexpr and_then_t<Self, F> and_then(Self &&self, F &&f)
{
    using result_t = and_then_t<Self, F>;
    static_assert(is_expected_v<result_t>, "and_then requires the callable to return an expected");
    if(self.has_value())
        return invoke_value(std::forward<Self>(self), std::forward<F>(f));
    return result_t(unexpect, std::forward<Self>(self).error());
}

template <typename Self, typename F>
constexpr or_else_t<Self, F> or_else(Self &&self, F &&f)
{
    using result_t = or_else_t<Self, F>;
    static_assert(is_expected_v<result_t>, "or_else requires the callable to return an expected");
    if(self.has_value())
        return from_value<result_t>(std::forward<Self>(self));
    return std::invoke(std::forward<F>(f), std::forward<Self>(self).error());
}

template <typename Self, typename F>
constexpr transform_t<Self, F> transform(Self &&self, F &&f)
{
    using result_t = transform_t<Self, F>;
    if(!self.has_value())
        return result_t(unexpect, std::forward<Self>(self).error());
    if constexpr(std::is_void_v<typename result_t::value_type>)
    {
        invoke_value(std::forward<Self>(self), std::forward<F>(f));
        return result_t();
    }
    else
        return result_t(std::in_place, invoke_value(std::forward<Self>(self), std::forward<F>(f)));
}

template <typename Self, typename F>
constexpr transform_error_t<Self, F> transform_error(Self &&self, F &&f)
{
    using result_t = transform_error_t<Self, F>;
    if(self.has_value())
        return from_value<result_t>(std::forward<Self>(self));
    return result_t(unexpect, std::invoke(std::forward<F>(f), std::forward<Self>(self).error()));
}

}

#endif
