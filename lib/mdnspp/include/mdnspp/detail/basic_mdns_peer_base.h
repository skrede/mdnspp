#ifndef HPP_GUARD_MDNSPP_DETAIL_BASIC_MDNS_PEER_BASE_H
#define HPP_GUARD_MDNSPP_DETAIL_BASIC_MDNS_PEER_BASE_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/recv_loop.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

/// Validates the protocol tunables shared by all peers.
///
/// Returns std::errc::invalid_argument when a field combination would produce
/// undefined behaviour (uniform_int_distribution with min > max) or violate
/// RFC 6762 scheduling invariants (shrinking backoff, thresholds outside (0,1)).
[[nodiscard]] inline std::error_code validate_mdns_options(const mdns_options &opts) noexcept
{
    const auto invalid = std::make_error_code(std::errc::invalid_argument);

    if(opts.response_delay_min.count() < 0 || opts.response_delay_min > opts.response_delay_max)
        return invalid;
    if(opts.tc_wait_min.count() < 0 || opts.tc_wait_min > opts.tc_wait_max)
        return invalid;
    if(opts.initial_interval.count() <= 0 || opts.max_interval < opts.initial_interval)
        return invalid;
    if(opts.backoff_multiplier < 1.0)
        return invalid;
    if(opts.refresh_jitter_pct < 0.0)
        return invalid;
    if(opts.ka_suppression_fraction <= 0.0 || opts.ka_suppression_fraction >= 1.0)
        return invalid;
    if(opts.tc_suppression_fraction <= 0.0 || opts.tc_suppression_fraction >= 1.0)
        return invalid;
    for(double threshold : opts.ttl_refresh_thresholds)
    {
        if(threshold <= 0.0 || threshold >= 1.0)
            return invalid;
    }

    return {};
}

/// Throws std::system_error(ec) when ec is set -- throwing-constructor companion
/// to the ec-reporting validation path.
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

    /// Posts fn to the executor guarded by the alive sentinel -- used to
    /// complete misuse (double-start) handlers without invoking them inline.
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
