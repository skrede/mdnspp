#ifndef HPP_GUARD_MDNSPP_DETAIL_COMPAT_H
#define HPP_GUARD_MDNSPP_DETAIL_COMPAT_H

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <variant>
#include <version>

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
#  include <expected>
#endif

namespace mdnspp::detail {

// --- move_only_function compat ---

#if defined(__cpp_lib_move_only_function) && __cpp_lib_move_only_function >= 202110L
template <typename Sig>
using move_only_function = std::move_only_function<Sig>;
#else

// Minimal move-only function wrapper for platforms without std::move_only_function.
// Unlike std::function, this supports move-only callables (e.g. asio awaitable_handler).
template <typename Sig>
class move_only_function; // primary template left undefined

template <typename R, typename... Args>
class move_only_function<R(Args...)>
{
    struct concept_t
    {
        virtual ~concept_t() = default;
        virtual R invoke(Args...) = 0;
    };

    template <typename F>
    struct model_t final : concept_t
    {
        F fn;
        explicit model_t(F f) : fn(std::move(f)) {}
        R invoke(Args... args) override { return fn(std::forward<Args>(args)...); }
    };

    std::unique_ptr<concept_t> m_impl;

public:
    move_only_function() = default;
    move_only_function(std::nullptr_t) noexcept {}

    template <typename F,
              std::enable_if_t<!std::is_same_v<std::remove_cvref_t<F>, move_only_function> &&
                               std::is_invocable_r_v<R, F &, Args...>, int> = 0>
    // NOLINTNEXTLINE(google-explicit-constructor)
    move_only_function(F f) : m_impl(std::make_unique<model_t<std::decay_t<F>>>(std::move(f))) {}

    move_only_function(move_only_function &&) noexcept = default;
    move_only_function &operator=(move_only_function &&) noexcept = default;

    move_only_function(const move_only_function &) = delete;
    move_only_function &operator=(const move_only_function &) = delete;

    explicit operator bool() const noexcept { return m_impl != nullptr; }

    R operator()(Args... args) { return m_impl->invoke(std::forward<Args>(args)...); }
};

#endif

// --- expected/unexpected compat ---

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
template <typename T, typename E>
using expected = std::expected<T, E>;

template <typename E>
auto make_unexpected(E e) { return std::unexpected<E>(std::move(e)); }
#else

template <typename E>
struct unexpected
{
    E value;

    explicit constexpr unexpected(E e) : value(std::move(e))
    {
    }
};

template <typename T, typename E>
class expected
{
    std::variant<T, unexpected<E>> m_storage;

public:
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr expected(T val) : m_storage(std::move(val))
    {
    }

    template <typename U,
              std::enable_if_t<std::is_constructible_v<T, U> &&
                               !std::is_same_v<std::remove_cvref_t<U>, expected>, int> = 0>
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr expected(U &&val) : m_storage(T(std::forward<U>(val)))
    {
    }

    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr expected(unexpected<E> err) : m_storage(std::move(err))
    {
    }

    constexpr explicit operator bool() const noexcept { return m_storage.index() == 0; }
    constexpr bool has_value() const noexcept { return m_storage.index() == 0; }

    constexpr T &operator*() & { return std::get<0>(m_storage); }
    constexpr const T &operator*() const & { return std::get<0>(m_storage); }
    constexpr T &&operator*() && { return std::get<0>(std::move(m_storage)); }

    constexpr T &value() & { return std::get<0>(m_storage); }
    constexpr const T &value() const & { return std::get<0>(m_storage); }

    constexpr const E &error() const & { return std::get<1>(m_storage).value; }
};

template <typename E>
constexpr auto make_unexpected(E e) { return unexpected<E>(std::move(e)); }

#endif

} // namespace mdnspp::detail

#endif // HPP_GUARD_MDNSPP_DETAIL_COMPAT_H
