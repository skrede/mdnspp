#ifndef HPP_GUARD_MDNSPP_DETAIL_EXPECTED_VOID_H
#define HPP_GUARD_MDNSPP_DETAIL_EXPECTED_VOID_H

#include "mdnspp/detail/unexpected.h"
#include "mdnspp/detail/expected_reinit.h"
#include "mdnspp/detail/expected_compare.h"
#include "mdnspp/detail/bad_expected_access.h"
#include "mdnspp/detail/expected_monadic_ops.h"

#include <variant>
#include <utility>
#include <type_traits>
#include <initializer_list>

namespace mdnspp::detail {

template <typename E>
class expected<void, E> : public expected_monadic_ops<expected<void, E>>
{
    using storage_t = std::variant<std::monostate, E>;

public:
    using value_type = void;
    using error_type = E;
    using unexpected_type = unexpected<E>;

    constexpr expected() noexcept : m_storage(std::in_place_index<0>)
    {
    }

    constexpr expected(const expected &) = default;
    constexpr expected(expected &&) = default;

    template <typename U, typename G>
        requires(std::is_void_v<U> && std::is_constructible_v<E, const G &> &&
                 !from_any_cvref_v<unexpected<E>, expected<U, G>>)
    constexpr explicit(!std::is_convertible_v<const G &, E>) expected(const expected<U, G> &other)
        : m_storage(convert(other))
    {
    }

    template <typename U, typename G>
        requires(std::is_void_v<U> && std::is_constructible_v<E, G> &&
                 !from_any_cvref_v<unexpected<E>, expected<U, G>>)
    constexpr explicit(!std::is_convertible_v<G, E>) expected(expected<U, G> &&other)
        : m_storage(convert(std::move(other)))
    {
    }

    template <typename G>
        requires std::is_constructible_v<E, const G &>
    constexpr explicit(!std::is_convertible_v<const G &, E>) expected(const unexpected<G> &e)
        : m_storage(std::in_place_index<1>, e.error())
    {
    }

    template <typename G>
        requires std::is_constructible_v<E, G>
    constexpr explicit(!std::is_convertible_v<G, E>) expected(unexpected<G> &&e)
        : m_storage(std::in_place_index<1>, std::move(e).error())
    {
    }

    constexpr explicit expected(std::in_place_t) noexcept : m_storage(std::in_place_index<0>)
    {
    }

    template <typename... Args>
        requires std::is_constructible_v<E, Args...>
    constexpr explicit expected(unexpect_t, Args &&...args)
        : m_storage(std::in_place_index<1>, std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args>
        requires std::is_constructible_v<E, std::initializer_list<U> &, Args...>
    constexpr explicit expected(unexpect_t, std::initializer_list<U> il, Args &&...args)
        : m_storage(std::in_place_index<1>, il, std::forward<Args>(args)...)
    {
    }

    constexpr expected &operator=(const expected &) requires std::is_trivially_copy_assignable_v<storage_t> = default;

    constexpr expected &operator=(const expected &other)
        requires(!std::is_trivially_copy_assignable_v<storage_t> && copy_reassignable_v<std::monostate, E>)
    {
        assign_from(m_storage, other.m_storage);
        return *this;
    }

    constexpr expected &operator=(expected &&) requires std::is_trivially_move_assignable_v<storage_t> = default;

    constexpr expected &operator=(expected &&other) noexcept(nothrow_move_reassignable_v<std::monostate, E>)
        requires(!std::is_trivially_move_assignable_v<storage_t> && move_reassignable_v<std::monostate, E>)
    {
        assign_from(m_storage, std::move(other.m_storage));
        return *this;
    }

    template <typename G>
        requires(std::is_constructible_v<E, const G &> && std::is_assignable_v<E &, const G &>)
    constexpr expected &operator=(const unexpected<G> &e)
    {
        return assign_error(e.error());
    }

    template <typename G>
        requires(std::is_constructible_v<E, G> && std::is_assignable_v<E &, G>)
    constexpr expected &operator=(unexpected<G> &&e)
    {
        return assign_error(std::move(e).error());
    }

    constexpr void emplace() noexcept { m_storage.template emplace<0>(); }

    constexpr void swap(expected &other) noexcept(std::is_nothrow_swappable_v<storage_t>)
        requires std::is_swappable_v<storage_t>
    {
        m_storage.swap(other.m_storage);
    }

    friend constexpr void swap(expected &x, expected &y) noexcept(noexcept(x.swap(y)))
        requires std::is_swappable_v<storage_t>
    {
        x.swap(y);
    }

    constexpr bool has_value() const noexcept { return m_storage.index() == 0; }
    constexpr explicit operator bool() const noexcept { return has_value(); }

    constexpr void operator*() const noexcept {}

    constexpr void value() const &
    {
        require_value(*this);
    }

    constexpr void value() &&
    {
        require_value(std::move(*this));
    }

    constexpr const E &error() const & noexcept { return std::get<1>(m_storage); }
    constexpr E &error() & noexcept { return std::get<1>(m_storage); }
    constexpr const E &&error() const && noexcept { return std::get<1>(std::move(m_storage)); }
    constexpr E &&error() && noexcept { return std::get<1>(std::move(m_storage)); }

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

private:
    storage_t m_storage;

    template <typename Other>
    static constexpr storage_t convert(Other &&other)
    {
        if(other.has_value())
            return storage_t(std::in_place_index<0>);
        return storage_t(std::in_place_index<1>, std::forward<Other>(other).error());
    }

    template <typename Self>
    static constexpr void require_value(Self &&self)
    {
        if(!self.has_value())
            throw bad_expected_access<E>(std::forward<Self>(self).error());
    }

    template <typename G>
    constexpr expected &assign_error(G &&error)
    {
        assign_alternative<1>(m_storage, std::forward<G>(error));
        return *this;
    }
};

}

#endif
