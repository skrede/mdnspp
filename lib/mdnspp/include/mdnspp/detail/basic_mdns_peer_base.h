#ifndef HPP_GUARD_MDNSPP_BASIC_MDNS_PEER_BASE_H
#define HPP_GUARD_MDNSPP_BASIC_MDNS_PEER_BASE_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/recv_loop.h"

#include <atomic>
#include <memory>
#include <cassert>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

template <Policy P>
class basic_mdns_peer_base
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    basic_mdns_peer_base(const basic_mdns_peer_base &) = delete;
    basic_mdns_peer_base &operator=(const basic_mdns_peer_base &) = delete;
    basic_mdns_peer_base &operator=(basic_mdns_peer_base &&) = delete;

protected:
    explicit basic_mdns_peer_base(executor_type ex, socket_options opts = {},
                                   mdns_options mdns_opts = {})
        : m_multicast_ep(opts.multicast_group)
        , m_executor(ex)
        , m_socket(ex, opts)
        , m_timer(ex)
        , m_stopped(false)
        , m_mdns_opts(std::move(mdns_opts))
    {
    }

    basic_mdns_peer_base(executor_type ex, socket_options opts, mdns_options mdns_opts,
                         std::error_code &ec)
        : m_multicast_ep(opts.multicast_group)
        , m_executor(ex)
        , m_socket(ex, opts, ec)
        , m_timer(ex)
        , m_stopped(false)
        , m_mdns_opts(std::move(mdns_opts))
    {
    }

    basic_mdns_peer_base(basic_mdns_peer_base &&other) noexcept
        : m_alive(std::move(other.m_alive))
        , m_multicast_ep(std::move(other.m_multicast_ep))
        , m_executor(other.m_executor)
        , m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_loop(std::move(other.m_loop))
        , m_stopped(other.m_stopped.load(std::memory_order_acquire))
        , m_mdns_opts(std::move(other.m_mdns_opts))
    {
        assert(other.m_loop == nullptr);
        other.m_stopped.store(true, std::memory_order_release);
    }

    ~basic_mdns_peer_base()
    {
        m_alive.reset();
    }

    template <typename F>
    void stop(F &&teardown)
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        auto guard = std::weak_ptr<bool>(m_alive);
        P::post(m_executor, [guard, td = std::forward<F>(teardown)]()
        {
            if(!guard.lock()) return;
            td();
        });
    }

    const endpoint &multicast_endpoint() const noexcept { return m_multicast_ep; }
    const socket_type &socket() const noexcept { return m_socket; }
    socket_type &socket() noexcept { return m_socket; }
    const timer_type &timer() const noexcept { return m_timer; }
    timer_type &timer() noexcept { return m_timer; }
    const mdns_options &mdns_opts() const noexcept { return m_mdns_opts; }

    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    endpoint m_multicast_ep;
    executor_type m_executor;
    socket_type m_socket;
    timer_type m_timer;
    std::unique_ptr<recv_loop<P>> m_loop;
    std::atomic<bool> m_stopped;
    mdns_options m_mdns_opts;
};

}

#endif
