#ifndef HPP_GUARD_MDNSPP_DETAIL_UNEXPECTED_H
#define HPP_GUARD_MDNSPP_DETAIL_UNEXPECTED_H

#include <utility>
#include <type_traits>
#include <initializer_list>

namespace mdnspp::detail {

struct unexpect_t
{
    explicit unexpect_t() = default;
};

inline constexpr unexpect_t unexpect{};

template <typename E>
class unexpected;

template <typename T>
struct is_unexpected : std::false_type {};

template <typename E>
struct is_unexpected<unexpected<E>> : std::true_type {};

template <typename T>
inline constexpr bool is_unexpected_v = is_unexpected<T>::value;

template <typename E>
class unexpected
{
    static_assert(std::is_object_v<E> && !std::is_array_v<E> && !is_unexpected_v<E> &&
                      std::is_same_v<E, std::remove_cv_t<E>>,
                  "unexpected requires a cv-unqualified non-array object type");

public:
    constexpr unexpected(const unexpected &) = default;
    constexpr unexpected(unexpected &&) = default;

    template <typename Err = E>
        requires(!std::is_same_v<std::remove_cvref_t<Err>, unexpected> &&
                 !std::is_same_v<std::remove_cvref_t<Err>, std::in_place_t> && std::is_constructible_v<E, Err>)
    constexpr explicit unexpected(Err &&e) : m_error(std::forward<Err>(e))
    {
    }

    template <typename... Args>
        requires std::is_constructible_v<E, Args...>
    constexpr explicit unexpected(std::in_place_t, Args &&...args) : m_error(std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args>
        requires std::is_constructible_v<E, std::initializer_list<U> &, Args...>
    constexpr explicit unexpected(std::in_place_t, std::initializer_list<U> il, Args &&...args)
        : m_error(il, std::forward<Args>(args)...)
    {
    }

    constexpr unexpected &operator=(const unexpected &) = default;
    constexpr unexpected &operator=(unexpected &&) = default;

    constexpr const E &error() const & noexcept { return m_error; }
    constexpr E &error() & noexcept { return m_error; }
    constexpr const E &&error() const && noexcept { return std::move(m_error); }
    constexpr E &&error() && noexcept { return std::move(m_error); }

    constexpr void swap(unexpected &other) noexcept(std::is_nothrow_swappable_v<E>)
        requires std::is_swappable_v<E>
    {
        using std::swap;
        swap(m_error, other.m_error);
    }

    friend constexpr void swap(unexpected &x, unexpected &y) noexcept(noexcept(x.swap(y)))
        requires std::is_swappable_v<E>
    {
        x.swap(y);
    }

    template <typename E2>
    friend constexpr bool operator==(const unexpected &x, const unexpected<E2> &y)
    {
        return x.error() == y.error();
    }

private:
    E m_error;
};

template <typename E>
unexpected(E) -> unexpected<E>;

}

#endif
