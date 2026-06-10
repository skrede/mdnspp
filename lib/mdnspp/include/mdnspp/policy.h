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
#include <optional>
#include <type_traits>
#include <system_error>

namespace mdnspp {

namespace detail {

// Dependent-false for static_assert in uninstantiated template branches.
// C++20 still requires a dependent expression here (P2593 is C++26).
template <typename T>
struct always_false : std::false_type
{
};

// Resolves the socket options type of a policy: P::socket_options_type when P
// declares one derived from socket_options, plain socket_options otherwise.
template <typename P>
struct policy_socket_options
{
    using type = socket_options;
};

template <typename P>
    requires std::derived_from<typename P::socket_options_type, socket_options>
struct policy_socket_options<P>
{
    using type = typename P::socket_options_type;
};

// RFC 6762 §17: multicast DNS messages must fit in a single packet of at most
// 9000 bytes including IP and UDP headers. Receive buffers use the full bound.
inline constexpr std::size_t max_udp_payload = 9000;

}

template <typename P>
using policy_socket_options_t = typename detail::policy_socket_options<P>::type;

/// Metadata carried with each received packet.
/// Passed to the socket handler and forwarded through recv_loop to packet handlers.
struct recv_metadata
{
    endpoint sender;
    std::optional<uint8_t> ttl;
    uint32_t recv_ifindex{0};
};

// socket_like<S>: satisfied by any type that provides the mDNS socket interface.
// The receive handler is invoked with the error code first (asio convention);
// on error the metadata is empty and the data span is empty.
//
// Semantic requirements (not expressible in the concept):
//   - Receive handlers fire on the policy executor; the library never locks
//     around handler invocation and relies on executor serialization.
//   - close() releases the pending receive handler; after close() no handler
//     may fire.
template <typename S>
concept socket_like = requires(S &s, const endpoint &ep, std::span<const std::byte> send_data, std::error_code &ec, move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
{
    { s.async_receive(std::move(handler)) } -> std::same_as<void>;
    { s.send(ep, send_data) } -> std::same_as<void>;
    { s.send(ep, send_data, ec) } -> std::same_as<void>;
    { s.close() } -> std::same_as<void>;
};

// timer_like<T>: satisfied by any type that provides the mDNS timer interface.
//
// Semantic requirements (not expressible in the concept):
//   - cancel() completes every pending async_wait with an error code equal to
//     operation_aborted/operation_canceled; every stop() path waits on this.
//   - expires_after() on a timer with a pending wait also cancels that wait.
//   - Wait handlers fire on the policy executor.
template <typename T>
concept timer_like = requires(T &t, std::chrono::milliseconds dur, move_only_function<void(std::error_code)> handler)
{
    t.expires_after(dur); // no return constraint — asio::steady_timer returns std::size_t
    { t.async_wait(std::move(handler)) } -> std::same_as<void>;
    { t.cancel() } -> std::same_as<void>;
};

// policy_like<P>: the unified policy concept.
// A policy bundles an executor type with a socket type and timer type,
// both constructible from the executor (matching ASIO convention).
//
// Semantic requirements (not expressible in the concept):
//   - P::post(ex, fn) must be callable from any thread; the peers use it to
//     marshal stop()/update_* requests onto the executor.
//   - Work posted via P::post runs on the executor, serialized with socket
//     receive handlers and timer wait handlers.
template <typename P>
concept policy_like = requires
    {
        typename P::executor_type;
        typename P::socket_type;
        typename P::timer_type;
    }
    && socket_like<typename P::socket_type>
    && timer_like<typename P::timer_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type>
    && std::constructible_from<typename P::timer_type, typename P::executor_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::timer_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const policy_socket_options_t<P>&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const policy_socket_options_t<P>&, std::error_code&>
    && requires(typename P::executor_type ex, move_only_function<void()> fn)
    {
        P::post(ex, std::move(fn));
    };

}

#endif
