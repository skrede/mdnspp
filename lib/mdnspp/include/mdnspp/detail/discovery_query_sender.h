#ifndef HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_QUERY_SENDER_H
#define HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_QUERY_SENDER_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/qu_history.h"
#include "mdnspp/detail/policy_clock.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/callback_types.h"

#include <span>
#include <atomic>
#include <chrono>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

// Sends a discovery query: QU immediately; QM after a random delay in
// [response_delay_min, response_delay_max] (RFC 6762 section 5.2).
template <policy_like P>
class discovery_query_sender
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    discovery_query_sender(executor_type ex, socket_type &socket, const endpoint &destination,
                           const mdns_options &opts, const std::atomic<bool> &stopped,
                           qu_history<policy_clock_t<P>> &history, error_handler &on_error)
        : m_timer(ex)
        , m_rng(std::random_device{}())
        , m_socket(socket)
        , m_on_error(on_error)
        , m_opts(opts)
        , m_destination(destination)
        , m_stopped(stopped)
        , m_history(history)
    {
    }

    discovery_query_sender(const discovery_query_sender &) = delete;
    discovery_query_sender &operator=(const discovery_query_sender &) = delete;

    const timer_type &timer() const noexcept { return m_timer; }
    timer_type &timer() noexcept { return m_timer; }

    void send(std::vector<std::byte> query_bytes, response_mode mode, std::string_view context)
    {
        if(mode == response_mode::unicast)
        {
            send_now(std::span<const std::byte>(query_bytes), context);
            return;
        }
        send_delayed(std::move(query_bytes), context);
    }

private:
    timer_type m_timer;
    std::mt19937 m_rng;
    socket_type &m_socket;
    error_handler &m_on_error;
    const mdns_options &m_opts;
    const endpoint &m_destination;
    const std::atomic<bool> &m_stopped;
    qu_history<policy_clock_t<P>> &m_history;

    void send_now(std::span<const std::byte> bytes, std::string_view context)
    {
        std::error_code ec;
        m_socket.send(m_destination, bytes, ec);
        if(!ec)
            m_history.record_sent(bytes);
        else if(m_on_error)
            m_on_error(ec, context);
    }

    void send_delayed(std::vector<std::byte> query_bytes, std::string_view context)
    {
        std::uniform_int_distribution<int32_t> dist(
            static_cast<int32_t>(m_opts.response_delay_min.count()),
            static_cast<int32_t>(m_opts.response_delay_max.count()));
        m_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_timer.async_wait(
            [this, bytes = std::move(query_bytes), context](std::error_code ec)
            {
                if(ec || m_stopped.load(std::memory_order_acquire))
                    return;
                send_now(std::span<const std::byte>(bytes), context);
            });
    }
};

}

#endif
