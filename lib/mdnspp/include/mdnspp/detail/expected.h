#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_H

#include "mdnspp/detail/unexpected.h"
#include "mdnspp/detail/expected_void.h"
#include "mdnspp/detail/expected_compare.h"
#include "mdnspp/detail/expected_storage.h"
#include "mdnspp/detail/expected_monadic_ops.h"

#include <variant>
#include <utility>
#include <cstddef>
#include <type_traits>
#include <initializer_list>

namespace mdnspp::detail {

template <typename T, typename E>
class expected : public expected_storage<T, E>, public expected_monadic_ops<expected<T, E>>
{
    using storage_t = std::variant<T, E>;

public:
    using value_type = T;
    using error_type = E;
    using unexpected_type = unexpected<E>;

    constexpr expected() requires std::is_default_constructible_v<T> : expected_storage<T, E>(std::in_place_index<0>)
    {
    }

    constexpr expected(const expected &) = default;
    constexpr expected(expected &&) = default;

    template <typename U, typename G>
        requires(std::is_constructible_v<T, const U &> && std::is_constructible_v<E, const G &> &&
                 expected_converts_v<T, E, U, G>)
    constexpr explicit(!std::is_convertible_v<const U &, T> || !std::is_convertible_v<const G &, E>)
        expected(const expected<U, G> &other) : expected_storage<T, E>(from_expected, other)
    {
    }

    template <typename U, typename G>
        requires(std::is_constructible_v<T, U> && std::is_constructible_v<E, G> && expected_converts_v<T, E, U, G>)
    constexpr explicit(!std::is_convertible_v<U, T> || !std::is_convertible_v<G, E>)
        expected(expected<U, G> &&other) : expected_storage<T, E>(from_expected, std::move(other))
    {
    }

    template <typename U = T>
        requires(!std::is_same_v<std::remove_cvref_t<U>, std::in_place_t> &&
                 !std::is_same_v<expected, std::remove_cvref_t<U>> && !is_unexpected_v<std::remove_cvref_t<U>> &&
                 std::is_constructible_v<T, U> &&
                 (!std::is_same_v<std::remove_cv_t<T>, bool> || !is_expected_v<std::remove_cvref_t<U>>))
    constexpr explicit(!std::is_convertible_v<U, T>) expected(U &&v)
        : expected_storage<T, E>(std::in_place_index<0>, std::forward<U>(v))
    {
    }

    template <typename G>
        requires std::is_constructible_v<E, const G &>
    constexpr explicit(!std::is_convertible_v<const G &, E>) expected(const unexpected<G> &e)
        : expected_storage<T, E>(std::in_place_index<1>, e.error())
    {
    }

    template <typename G>
        requires std::is_constructible_v<E, G>
    constexpr explicit(!std::is_convertible_v<G, E>) expected(unexpected<G> &&e)
        : expected_storage<T, E>(std::in_place_index<1>, std::move(e).error())
    {
    }

    template <typename... Args>
        requires std::is_constructible_v<T, Args...>
    constexpr explicit expected(std::in_place_t, Args &&...args)
        : expected_storage<T, E>(std::in_place_index<0>, std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args>
        requires std::is_constructible_v<T, std::initializer_list<U> &, Args...>
    constexpr explicit expected(std::in_place_t, std::initializer_list<U> il, Args &&...args)
        : expected_storage<T, E>(std::in_place_index<0>, il, std::forward<Args>(args)...)
    {
    }

    template <typename... Args>
        requires std::is_constructible_v<E, Args...>
    constexpr explicit expected(unexpect_t, Args &&...args)
        : expected_storage<T, E>(std::in_place_index<1>, std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args>
        requires std::is_constructible_v<E, std::initializer_list<U> &, Args...>
    constexpr explicit expected(unexpect_t, std::initializer_list<U> il, Args &&...args)
        : expected_storage<T, E>(std::in_place_index<1>, il, std::forward<Args>(args)...)
    {
    }

    constexpr expected &operator=(const expected &) = default;
    constexpr expected &operator=(expected &&) = default;

    template <typename U = T>
        requires(!std::is_same_v<expected, std::remove_cvref_t<U>> && !is_unexpected_v<std::remove_cvref_t<U>> &&
                 std::is_constructible_v<T, U> && std::is_assignable_v<T &, U>)
    constexpr expected &operator=(U &&v)
    {
        return assign<0>(std::forward<U>(v));
    }

    template <typename G>
        requires(std::is_constructible_v<E, const G &> && std::is_assignable_v<E &, const G &>)
    constexpr expected &operator=(const unexpected<G> &e)
    {
        return assign<1>(e.error());
    }

    template <typename G>
        requires(std::is_constructible_v<E, G> && std::is_assignable_v<E &, G>)
    constexpr expected &operator=(unexpected<G> &&e)
    {
        return assign<1>(std::move(e).error());
    }

    template <typename... Args>
        requires std::is_nothrow_constructible_v<T, Args...>
    constexpr T &emplace(Args &&...args) noexcept
    {
        return this->storage().template emplace<0>(std::forward<Args>(args)...);
    }

    template <typename U, typename... Args>
        requires std::is_nothrow_constructible_v<T, std::initializer_list<U> &, Args...>
    constexpr T &emplace(std::initializer_list<U> il, Args &&...args) noexcept
    {
        return this->storage().template emplace<0>(il, std::forward<Args>(args)...);
    }

    constexpr void swap(expected &other) noexcept(std::is_nothrow_swappable_v<storage_t>)
        requires std::is_swappable_v<storage_t>
    {
        this->storage().swap(other.storage());
    }

    friend constexpr void swap(expected &x, expected &y) noexcept(noexcept(x.swap(y)))
        requires std::is_swappable_v<storage_t>
    {
        x.swap(y);
    }

private:
    template <size_t Index, typename Arg>
    constexpr expected &assign(Arg &&arg)
    {
        if(this->storage().index() == Index)
            std::get<Index>(this->storage()) = std::forward<Arg>(arg);
        else
            this->storage().template emplace<Index>(std::forward<Arg>(arg));
        return *this;
    }
};

}

#endif
