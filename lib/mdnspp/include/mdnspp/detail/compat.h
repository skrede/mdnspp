#ifndef HPP_GUARD_MDNSPP_DETAIL_COMPAT_H
#define HPP_GUARD_MDNSPP_DETAIL_COMPAT_H

#include <functional>
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
template <typename Sig>
using move_only_function = std::function<Sig>;
#endif

// --- expected/unexpected compat ---

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
template <typename T, typename E>
using expected = std::expected<T, E>;

template <typename E>
using unexpected = std::unexpected<E>;
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

#endif

} // namespace mdnspp::detail

#endif // HPP_GUARD_MDNSPP_DETAIL_COMPAT_H
