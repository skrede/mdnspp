#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_STORAGE_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_STORAGE_H

#include "mdnspp/detail/bad_expected_access.h"

#include <memory>
#include <variant>
#include <utility>
#include <cstddef>

namespace mdnspp::detail {

struct from_expected_t
{
    explicit from_expected_t() = default;
};

inline constexpr from_expected_t from_expected{};

template <typename T, typename E>
class expected_storage
{
protected:
    using storage_t = std::variant<T, E>;

public:
    constexpr bool has_value() const noexcept { return m_storage.index() == 0; }
    constexpr explicit operator bool() const noexcept { return has_value(); }

    constexpr const T *operator->() const noexcept { return std::addressof(std::get<0>(m_storage)); }
    constexpr T *operator->() noexcept { return std::addressof(std::get<0>(m_storage)); }

    constexpr const T &operator*() const & noexcept { return std::get<0>(m_storage); }
    constexpr T &operator*() & noexcept { return std::get<0>(m_storage); }
    constexpr const T &&operator*() const && noexcept { return std::get<0>(std::move(m_storage)); }
    constexpr T &&operator*() && noexcept { return std::get<0>(std::move(m_storage)); }

    constexpr const T &value() const &
    {
        require_value(*this);
        return std::get<0>(m_storage);
    }

    constexpr T &value() &
    {
        require_value(*this);
        return std::get<0>(m_storage);
    }

    constexpr const T &&value() const &&
    {
        require_value(std::move(*this));
        return std::get<0>(std::move(m_storage));
    }

    constexpr T &&value() &&
    {
        require_value(std::move(*this));
        return std::get<0>(std::move(m_storage));
    }

    constexpr const E &error() const & noexcept { return std::get<1>(m_storage); }
    constexpr E &error() & noexcept { return std::get<1>(m_storage); }
    constexpr const E &&error() const && noexcept { return std::get<1>(std::move(m_storage)); }
    constexpr E &&error() && noexcept { return std::get<1>(std::move(m_storage)); }

    template <typename U = std::remove_cv_t<T>>
    constexpr T value_or(U &&fallback) const &
    {
        return has_value() ? **this : static_cast<T>(std::forward<U>(fallback));
    }

    template <typename U = std::remove_cv_t<T>>
    constexpr T value_or(U &&fallback) &&
    {
        return has_value() ? std::move(**this) : static_cast<T>(std::forward<U>(fallback));
    }

    template <typename G = E>
    constexpr E error_or(G &&fallback) const &
    {
        return has_value() ? static_cast<E>(std::forward<G>(fallback)) : error();
    }

    template <typename G = E>
    constexpr E error_or(G &&fallback) &&
    {
        return has_value() ? static_cast<E>(std::forward<G>(fallback)) : std::move(*this).error();
    }

protected:
    template <size_t Index, typename... Args>
    constexpr explicit expected_storage(std::in_place_index_t<Index>, Args &&...args)
        : m_storage(std::in_place_index<Index>, std::forward<Args>(args)...)
    {
    }

    template <typename Other>
    constexpr expected_storage(from_expected_t, Other &&other) : m_storage(convert(std::forward<Other>(other)))
    {
    }

    constexpr expected_storage(const expected_storage &) = default;
    constexpr expected_storage(expected_storage &&) = default;
    constexpr expected_storage &operator=(const expected_storage &) = default;
    constexpr expected_storage &operator=(expected_storage &&) = default;

    constexpr storage_t &storage() noexcept { return m_storage; }
    constexpr const storage_t &storage() const noexcept { return m_storage; }

private:
    storage_t m_storage;

    template <typename Other>
    static constexpr storage_t convert(Other &&other)
    {
        if(other.has_value())
            return storage_t(std::in_place_index<0>, *std::forward<Other>(other));
        return storage_t(std::in_place_index<1>, std::forward<Other>(other).error());
    }

    template <typename Self>
    static constexpr void require_value(Self &&self)
    {
        if(!self.has_value())
            throw bad_expected_access<E>(std::forward<Self>(self).error());
    }
};

}

#endif
