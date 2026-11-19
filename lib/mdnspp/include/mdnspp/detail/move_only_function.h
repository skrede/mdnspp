#ifndef HPP_GUARD_MDNSPP_DETAIL_MOVE_ONLY_FUNCTION_H
#define HPP_GUARD_MDNSPP_DETAIL_MOVE_ONLY_FUNCTION_H

#include <new>
#include <memory>
#include <utility>
#include <cstddef>
#include <functional>
#include <type_traits>

namespace mdnspp::detail {

template <typename Sig>
class move_only_function;

template <typename R, typename... Args>
class move_only_function<R(Args...)>
{
    struct operations
    {
        R (*invoke)(void *, Args &&...);
        void (*relocate)(void *from, void *to) noexcept;
        void (*destroy)(void *) noexcept;
    };

    template <typename Holder>
    struct model
    {
        template <typename F>
        static F &target(F &fn) noexcept
        {
            return fn;
        }

        template <typename F>
        static F &target(std::unique_ptr<F> &fn) noexcept
        {
            return *fn;
        }

        static Holder &object(void *self) noexcept
        {
            return *std::launder(static_cast<Holder *>(self));
        }

        static R invoke(void *self, Args &&...args)
        {
            if constexpr(std::is_void_v<R>)
                static_cast<void>(std::invoke(target(object(self)), std::forward<Args>(args)...));
            else
                return std::invoke(target(object(self)), std::forward<Args>(args)...);
        }

        static void relocate(void *from, void *to) noexcept
        {
            ::new(to) Holder(std::move(object(from)));
            object(from).~Holder();
        }

        static void destroy(void *self) noexcept
        {
            object(self).~Holder();
        }

        static constexpr operations table{&invoke, &relocate, &destroy};
    };

public:
    // Large enough for every closure the library builds per datagram, post and timer wait.
    static constexpr std::size_t inline_capacity = 56;

    // The single check deciding inline versus heap storage.
    template <typename F>
    static constexpr bool stored_inline = sizeof(F) <= inline_capacity
        && alignof(F) <= alignof(std::max_align_t) && std::is_nothrow_move_constructible_v<F>;

    move_only_function() noexcept
        : m_ops(nullptr)
    {
    }

    move_only_function(std::nullptr_t) noexcept
        : m_ops(nullptr)
    {
    }

    template <typename F, typename D = std::decay_t<F>>
        requires (!std::is_same_v<std::remove_cvref_t<F>, move_only_function>
                  && std::is_constructible_v<D, F> && std::is_invocable_r_v<R, D &, Args...>)
    // NOLINTNEXTLINE(google-explicit-constructor)
    move_only_function(F &&fn)
        : m_ops(nullptr)
    {
        if constexpr(std::is_pointer_v<std::remove_cvref_t<F>> || std::is_member_pointer_v<D>)
        {
            if(fn == nullptr)
                return;
        }
        if constexpr(stored_inline<D>)
            ::new(static_cast<void *>(m_buffer)) D(std::forward<F>(fn));
        else
            ::new(static_cast<void *>(m_buffer)) std::unique_ptr<D>(std::make_unique<D>(std::forward<F>(fn)));
        m_ops = &model<holder<D>>::table;
    }

    move_only_function(move_only_function &&other) noexcept
        : m_ops(nullptr)
    {
        take(other);
    }

    move_only_function(const move_only_function &) = delete;
    move_only_function &operator=(const move_only_function &) = delete;

    move_only_function &operator=(move_only_function &&other) noexcept
    {
        if(this != &other)
        {
            reset();
            take(other);
        }
        return *this;
    }

    move_only_function &operator=(std::nullptr_t) noexcept
    {
        reset();
        return *this;
    }

    ~move_only_function()
    {
        reset();
    }

    explicit operator bool() const noexcept { return m_ops != nullptr; }

    friend bool operator==(const move_only_function &fn, std::nullptr_t) noexcept { return !fn; }

    R operator()(Args... args) { return m_ops->invoke(m_buffer, std::forward<Args>(args)...); }

    void swap(move_only_function &other) noexcept
    {
        move_only_function held(std::move(other));
        other = std::move(*this);
        *this = std::move(held);
    }

    friend void swap(move_only_function &a, move_only_function &b) noexcept { a.swap(b); }

private:
    alignas(std::max_align_t) std::byte m_buffer[inline_capacity];
    const operations *m_ops;

    template <typename F>
    using holder = std::conditional_t<stored_inline<F>, F, std::unique_ptr<F>>;

    void take(move_only_function &other) noexcept
    {
        m_ops = std::exchange(other.m_ops, nullptr);
        if(m_ops)
            m_ops->relocate(other.m_buffer, m_buffer);
    }

    void reset() noexcept
    {
        if(m_ops)
            m_ops->destroy(m_buffer);
        m_ops = nullptr;
    }
};

}

#endif
