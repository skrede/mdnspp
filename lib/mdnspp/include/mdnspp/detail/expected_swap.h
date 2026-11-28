#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_SWAP_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_SWAP_H

#include "mdnspp/detail/expected_reinit.h"

#include <cstddef>
#include <utility>
#include <variant>
#include <type_traits>

namespace mdnspp::detail {

template <typename T, typename E>
inline constexpr bool swappable_alternatives_v = std::is_swappable_v<T> && std::is_swappable_v<E> &&
    std::is_move_constructible_v<T> && std::is_move_constructible_v<E> && either_nothrow_movable_v<T, E>;

template <typename T, typename E>
inline constexpr bool nothrow_swappable_alternatives_v = std::is_nothrow_move_constructible_v<T> &&
    std::is_nothrow_swappable_v<T> && std::is_nothrow_move_constructible_v<E> && std::is_nothrow_swappable_v<E>;

template <std::size_t Index, typename Variant>
constexpr void exchange_through_temporary(Variant &holder, Variant &other)
{
    using held_t = std::variant_alternative_t<Index, Variant>;
    static_assert(std::is_nothrow_move_constructible_v<held_t>, "one alternative must be nothrow movable");
    held_t temporary(std::move(std::get<Index>(holder)));
    try
    {
        holder.template emplace<1 - Index>(std::move(std::get<1 - Index>(other)));
    }
    catch(...)
    {
        holder.template emplace<Index>(std::move(temporary));
        throw;
    }
    other.template emplace<Index>(std::move(temporary));
}

// [expected.object.swap] and [expected.void.swap]: the alternative whose move may throw is moved exactly once.
template <typename Variant>
constexpr void exchange_alternatives(Variant &value_side, Variant &error_side)
{
    if constexpr(std::is_nothrow_move_constructible_v<std::variant_alternative_t<1, Variant>>)
        exchange_through_temporary<1>(error_side, value_side);
    else
        exchange_through_temporary<0>(value_side, error_side);
}

template <typename Variant>
constexpr void swap_storage(Variant &lhs, Variant &rhs)
{
    using std::swap;
    if(lhs.index() == 0 && rhs.index() == 0)
        swap(std::get<0>(lhs), std::get<0>(rhs));
    else if(lhs.index() == 1 && rhs.index() == 1)
        swap(std::get<1>(lhs), std::get<1>(rhs));
    else if(lhs.index() == 0)
        exchange_alternatives(lhs, rhs);
    else
        exchange_alternatives(rhs, lhs);
}

}

#endif
