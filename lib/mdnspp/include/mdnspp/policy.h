#ifndef HPP_GUARD_MDNSPP_POLICY_H
#define HPP_GUARD_MDNSPP_POLICY_H

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"

#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <concepts>
#include <functional>
#include <system_error>

namespace mdnspp {

namespace detail {

template <typename T>
struct always_false : std::false_type
{
};

}

/// Metadata carried with each received packet.
/// Passed to the socket handler and forwarded through recv_loop to packet handlers.
struct recv_metadata
{
    endpoint sender;
    uint8_t ttl{255};
};

// SocketLike<S>: satisfied by any type that provides the mDNS socket interface.
template <typename S>
concept SocketLike = requires(S &s, const endpoint &ep, std::span<const std::byte> send_data, std::error_code &ec, std::function<void(const recv_metadata &, std::span<std::byte>)> handler)
{
    { s.async_receive(handler) } -> std::same_as<void>;
    { s.send(ep, send_data) } -> std::same_as<void>;
    { s.send(ep, send_data, ec) } -> std::same_as<void>;
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
    && std::constructible_from<typename P::timer_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const socket_options&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const socket_options&, std::error_code&>
    && requires(typename P::executor_type ex, detail::move_only_function<void()> fn)
    {
        P::post(ex, std::move(fn));
    };

}

#endif
