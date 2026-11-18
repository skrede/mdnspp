#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_TRAITS_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_TRAITS_H

#include "mdnspp/detail/unexpected.h"

#include <utility>
#include <functional>
#include <type_traits>

namespace mdnspp::detail {

template <typename T, typename E>
class expected;

template <typename T>
struct is_expected : std::false_type {};

template <typename T, typename E>
struct is_expected<expected<T, E>> : std::true_type {};

template <typename T>
inline constexpr bool is_expected_v = is_expected<T>::value;

template <typename To, typename From>
inline constexpr bool from_any_cvref_v =
    std::is_constructible_v<To, From &> || std::is_constructible_v<To, From> ||
    std::is_constructible_v<To, const From &> || std::is_constructible_v<To, const From>;

template <typename T, typename E, typename U, typename G>
inline constexpr bool expected_converts_v =
    (std::is_same_v<std::remove_cv_t<T>, bool> || !from_any_cvref_v<T, expected<U, G>>) &&
    !from_any_cvref_v<unexpected<E>, expected<U, G>>;

template <typename Self, typename F, typename = typename std::remove_cvref_t<Self>::value_type>
struct value_invoke
{
    using type = std::invoke_result_t<F, decltype(*std::declval<Self>())>;
};

template <typename Self, typename F>
struct value_invoke<Self, F, void>
{
    using type = std::invoke_result_t<F>;
};

template <typename Self, typename F>
using value_invoke_t = typename value_invoke<Self, F>::type;

template <typename Self, typename F>
using error_invoke_t = std::invoke_result_t<F, decltype(std::declval<Self>().error())>;

template <typename Self, typename F>
using and_then_t = std::remove_cvref_t<value_invoke_t<Self, F>>;

template <typename Self, typename F>
using or_else_t = std::remove_cvref_t<error_invoke_t<Self, F>>;

template <typename Self, typename F>
using transform_t =
    expected<std::remove_cv_t<value_invoke_t<Self, F>>, typename std::remove_cvref_t<Self>::error_type>;

template <typename Self, typename F>
using transform_error_t =
    expected<typename std::remove_cvref_t<Self>::value_type, std::remove_cv_t<error_invoke_t<Self, F>>>;

}

#endif
