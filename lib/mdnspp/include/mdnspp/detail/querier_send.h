#ifndef HPP_GUARD_MDNSPP_DETAIL_QUERIER_SEND_H
#define HPP_GUARD_MDNSPP_DETAIL_QUERIER_SEND_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/qu_history.h"
#include "mdnspp/detail/policy_clock.h"

#include "mdnspp/policy.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/callback_types.h"

#include <span>
#include <chrono>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

// A QM query waits a random delay in [response_delay_min, response_delay_max] and is dropped when another host
// asks the same question first (RFC 6762 section 7.3).
template <policy_like P>
class querier_sender
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    querier_sender(executor_type ex, socket_type &socket, const endpoint &destination, const mdns_options &opts,
                   qu_history<policy_clock_t<P>> &history, error_handler &on_error)
        : m_sent(false)
        , m_suppressed(false)
        , m_timer(ex)
        , m_rng(std::random_device()())
        , m_socket(socket)
        , m_on_error(on_error)
        , m_opts(opts)
        , m_destination(destination)
        , m_history(history)
    {
    }

    querier_sender(const querier_sender &) = delete;
    querier_sender &operator=(const querier_sender &) = delete;

    const timer_type &timer() const noexcept { return m_timer; }
    timer_type &timer() noexcept { return m_timer; }
    bool sent() const noexcept { return m_sent; }

    void reset() noexcept
    {
        m_sent = false;
        m_suppressed = false;
    }

    void suppress()
    {
        m_suppressed = true;
        m_timer.cancel();
    }

    void send_now(const dns_name &name, dns_type type, response_mode mode)
    {
        const std::vector<std::byte> query = build_dns_query(name, type, mode);
        std::error_code ec;
        m_socket.send(m_destination, std::span<const std::byte>(query), ec);
        if(!ec)
            m_history.record_sent(query);
        else if(m_on_error)
            m_on_error(ec, "query send");
        m_sent = true;
    }

    void send_delayed(dns_name name, dns_type type)
    {
        std::uniform_int_distribution<int32_t> dist(static_cast<int32_t>(m_opts.response_delay_min.count()),
                                                    static_cast<int32_t>(m_opts.response_delay_max.count()));
        m_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_timer.async_wait([this, name = std::move(name), type](std::error_code ec)
        {
            if(!ec && !m_suppressed)
                send_now(name, type, response_mode::multicast);
        });
    }

private:
    bool m_sent;
    bool m_suppressed;
    timer_type m_timer;
    std::mt19937 m_rng;
    socket_type &m_socket;
    error_handler &m_on_error;
    const mdns_options &m_opts;
    const endpoint &m_destination;
    qu_history<policy_clock_t<P>> &m_history;
};

}

#endif
