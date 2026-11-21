#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_REINIT_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_REINIT_H

#include <cstddef>
#include <utility>
#include <variant>
#include <type_traits>

namespace mdnspp::detail {

template <typename A, typename B>
inline constexpr bool either_nothrow_movable_v =
    std::is_nothrow_move_constructible_v<A> || std::is_nothrow_move_constructible_v<B>;

template <typename New, typename Old, typename... Args>
inline constexpr bool reinit_possible_v =
    std::is_nothrow_constructible_v<New, Args...> || either_nothrow_movable_v<New, Old>;

template <typename A, typename B>
inline constexpr bool copy_reassignable_v = std::is_copy_constructible_v<A> && std::is_copy_assignable_v<A> &&
    std::is_copy_constructible_v<B> && std::is_copy_assignable_v<B> && either_nothrow_movable_v<A, B>;

template <typename A, typename B>
inline constexpr bool move_reassignable_v = std::is_move_constructible_v<A> && std::is_move_assignable_v<A> &&
    std::is_move_constructible_v<B> && std::is_move_assignable_v<B> && either_nothrow_movable_v<A, B>;

template <typename A, typename B>
inline constexpr bool nothrow_move_reassignable_v = std::is_nothrow_move_constructible_v<A> &&
    std::is_nothrow_move_assignable_v<A> && std::is_nothrow_move_constructible_v<B> &&
    std::is_nothrow_move_assignable_v<B>;

template <std::size_t Index, typename Variant, typename... Args>
constexpr void reinit_through_backup(Variant &storage, Args &&...args)
{
    using old_t = std::variant_alternative_t<1 - Index, Variant>;
    static_assert(std::is_nothrow_move_constructible_v<old_t>, "one alternative must be nothrow movable");
    old_t backup(std::move(std::get<1 - Index>(storage)));
    try
    {
        storage.template emplace<Index>(std::forward<Args>(args)...);
    }
    catch(...)
    {
        storage.template emplace<1 - Index>(std::move(backup));
        throw;
    }
}

// The reinit-expected protocol of [expected.object.assign]: the old alternative survives a throwing replacement.
template <std::size_t Index, typename Variant, typename... Args>
constexpr void reinit_alternative(Variant &storage, Args &&...args)
{
    using new_t = std::variant_alternative_t<Index, Variant>;
    if constexpr(std::is_nothrow_constructible_v<new_t, Args...>)
        storage.template emplace<Index>(std::forward<Args>(args)...);
    else if constexpr(std::is_nothrow_move_constructible_v<new_t>)
    {
        new_t fresh(std::forward<Args>(args)...);
        storage.template emplace<Index>(std::move(fresh));
    }
    else
        reinit_through_backup<Index>(storage, std::forward<Args>(args)...);
}

template <std::size_t Index, typename Variant, typename Arg>
constexpr void assign_alternative(Variant &storage, Arg &&arg)
{
    if(storage.index() == Index)
        std::get<Index>(storage) = std::forward<Arg>(arg);
    else
        reinit_alternative<Index>(storage, std::forward<Arg>(arg));
}

template <typename Variant, typename Source>
constexpr void assign_from(Variant &storage, Source &&source)
{
    if(source.index() == 0)
        assign_alternative<0>(storage, std::get<0>(std::forward<Source>(source)));
    else
        assign_alternative<1>(storage, std::get<1>(std::forward<Source>(source)));
}

}

#endif
