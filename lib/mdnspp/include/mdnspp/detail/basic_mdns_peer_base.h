#ifndef HPP_GUARD_MDNSPP_DETAIL_BASIC_MDNS_PEER_BASE_H
#define HPP_GUARD_MDNSPP_DETAIL_BASIC_MDNS_PEER_BASE_H

#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/mdns_options_validation.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/socket_options.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

inline void throw_on_error(std::error_code ec)
{
    if(ec)
        throw std::system_error(ec);
}

template <policy_like P>
class basic_mdns_peer_base
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    // Non-copyable and non-movable: recv_loop handlers and posted teardown
    // lambdas capture `this`.
    basic_mdns_peer_base(const basic_mdns_peer_base &) = delete;
    basic_mdns_peer_base &operator=(const basic_mdns_peer_base &) = delete;
    basic_mdns_peer_base(basic_mdns_peer_base &&) = delete;
    basic_mdns_peer_base &operator=(basic_mdns_peer_base &&) = delete;

protected:
    explicit basic_mdns_peer_base(executor_type ex, policy_socket_options_t<P> opts = {},
                                   mdns_options mdns_opts = {})
        : m_multicast_ep(opts.multicast_group)
        , m_executor(ex)
        , m_socket(ex, opts)
        , m_timer(ex)
        , m_stopped(false)
        , m_mdns_opts(std::move(mdns_opts))
    {
    }

    basic_mdns_peer_base(executor_type ex, policy_socket_options_t<P> opts, mdns_options mdns_opts,
                         std::error_code &ec)
        : m_multicast_ep(opts.multicast_group)
        , m_executor(ex)
        , m_socket(ex, opts, ec)
        , m_timer(ex)
        , m_stopped(false)
        , m_mdns_opts(std::move(mdns_opts))
    {
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

    template <typename F>
    void post_guarded(F &&fn)
    {
        auto guard = std::weak_ptr<bool>(m_alive);
        P::post(m_executor, [guard, f = std::forward<F>(fn)]() mutable
        {
            if(!guard.lock()) return;
            f();
        });
    }

    std::error_code start_misuse(bool running) const noexcept
    {
        if(running)
            return std::make_error_code(std::errc::operation_in_progress);
        if(m_stopped.load(std::memory_order_acquire))
            return std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    // Leaves the loop unstarted: the server starts it only after its first probe is scheduled.
    void make_receive_loop(std::chrono::milliseconds silence_timeout,
                           typename recv_loop<P>::packet_handler on_packet,
                           move_only_function<void()> on_silence,
                           typename recv_loop<P>::error_handler on_error)
    {
        m_loop = std::make_unique<recv_loop<P>>(m_socket, m_timer, silence_timeout, std::move(on_packet),
                                                std::move(on_silence), m_mdns_opts.receive_ttl_minimum,
                                                m_mdns_opts.unknown_ttl_policy, std::move(on_error));
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
