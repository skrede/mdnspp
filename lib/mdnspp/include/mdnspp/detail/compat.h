#ifndef HPP_GUARD_MDNSPP_DETAIL_COMPAT_H
#define HPP_GUARD_MDNSPP_DETAIL_COMPAT_H

#include "mdnspp/detail/expected.h"
#include "mdnspp/detail/move_only_function.h"

#include <type_traits>

namespace mdnspp::detail {

// C++23 std::to_underlying (P1682).
template <typename E>
constexpr std::underlying_type_t<E> to_underlying(E e) noexcept
{
    return static_cast<std::underlying_type_t<E>>(e);
}

}

namespace mdnspp {

using detail::expected;
using detail::unexpected;
using detail::unexpect;
using detail::unexpect_t;
using detail::bad_expected_access;
using detail::move_only_function;

}

#endif
