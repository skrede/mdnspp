#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_MONADIC_OPS_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_MONADIC_OPS_H

#include "mdnspp/detail/expected_monadic.h"

#include <utility>

namespace mdnspp::detail {

// Self defaults to Derived so the result types are only formed at call time, when Derived is complete.
template <typename Derived>
class expected_monadic_ops
{
public:
    template <typename F, typename Self = Derived>
    constexpr and_then_t<Self &, F> and_then(F &&f) &
    {
        return monadic::and_then(static_cast<Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr and_then_t<const Self &, F> and_then(F &&f) const &
    {
        return monadic::and_then(static_cast<const Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr and_then_t<Self &&, F> and_then(F &&f) &&
    {
        return monadic::and_then(static_cast<Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr and_then_t<const Self &&, F> and_then(F &&f) const &&
    {
        return monadic::and_then(static_cast<const Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr or_else_t<Self &, F> or_else(F &&f) &
    {
        return monadic::or_else(static_cast<Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr or_else_t<const Self &, F> or_else(F &&f) const &
    {
        return monadic::or_else(static_cast<const Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr or_else_t<Self &&, F> or_else(F &&f) &&
    {
        return monadic::or_else(static_cast<Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr or_else_t<const Self &&, F> or_else(F &&f) const &&
    {
        return monadic::or_else(static_cast<const Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_t<Self &, F> transform(F &&f) &
    {
        return monadic::transform(static_cast<Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_t<const Self &, F> transform(F &&f) const &
    {
        return monadic::transform(static_cast<const Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_t<Self &&, F> transform(F &&f) &&
    {
        return monadic::transform(static_cast<Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_t<const Self &&, F> transform(F &&f) const &&
    {
        return monadic::transform(static_cast<const Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_error_t<Self &, F> transform_error(F &&f) &
    {
        return monadic::transform_error(static_cast<Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_error_t<const Self &, F> transform_error(F &&f) const &
    {
        return monadic::transform_error(static_cast<const Self &>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_error_t<Self &&, F> transform_error(F &&f) &&
    {
        return monadic::transform_error(static_cast<Self &&>(*this), std::forward<F>(f));
    }

    template <typename F, typename Self = Derived>
    constexpr transform_error_t<const Self &&, F> transform_error(F &&f) const &&
    {
        return monadic::transform_error(static_cast<const Self &&>(*this), std::forward<F>(f));
    }

protected:
    expected_monadic_ops() = default;
};

}

#endif
