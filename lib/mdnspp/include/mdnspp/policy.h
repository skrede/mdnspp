#ifndef HPP_GUARD_MDNSPP_POLICY_H
#define HPP_GUARD_MDNSPP_POLICY_H

#include <chrono>
#include <concepts>
#include <cstddef>
#include <functional>
#include <span>
#include <system_error>
#include "mdnspp/endpoint.h"

namespace mdnspp {

namespace detail {

template <typename T>
struct always_false : std::false_type
{
};

}

// SocketLike<S>: satisfied by any type that provides the mDNS socket interface.
template <typename S>
concept SocketLike = requires(S &s, endpoint ep, std::span<const std::byte> send_data, std::function<void(std::span<std::byte>, endpoint)> handler)
{
    { s.async_receive(handler) } -> std::same_as<void>;
    { s.send(ep, send_data) } -> std::same_as<void>;
    { s.close() } -> std::same_as<void>;
};

// TimerLike<T>: satisfied by any type that provides the mDNS timer interface.
template <typename T>
concept TimerLike = requires(T &t, std::chrono::milliseconds dur, std::function<void(std::error_code)> handler)
{
    t.expires_after(dur); // no return constraint — asio::steady_timer returns std::size_t
    { t.async_wait(handler) } -> std::same_as<void>;
    { t.cancel() } -> std::same_as<void>;
};

// Policy<P>: the unified policy concept.
// A Policy bundles an executor type with a socket type and timer type,
// both constructible from the executor (matching ASIO convention).
template <typename P>
concept Policy = requires
    {
        typename P::executor_type;
        typename P::socket_type;
        typename P::timer_type;
    }
    && SocketLike<typename P::socket_type>
    && TimerLike<typename P::timer_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type>
    && std::constructible_from<typename P::timer_type, typename P::executor_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::timer_type, typename P::executor_type, std::error_code&>;

}

#endif
