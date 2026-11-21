#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_QUERIER_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_QUERIER_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query_tc.h"
#include "mdnspp/detail/monitor_queries.h"
#include "mdnspp/detail/monitor_schedule.h"
#include "mdnspp/detail/monitor_tc_chains.h"

#include "mdnspp/policy.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/record_cache.h"
#include "mdnspp/monitor_options.h"

#include <span>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

template <policy_like P, typename Clock>
class monitor_querier
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    monitor_querier(executor_type ex, socket_type &socket, const endpoint &destination, record_cache<Clock> &cache,
                    monitor_options &opts, const mdns_options &mdns_opts, const std::atomic<bool> &stopped,
                    const std::shared_ptr<bool> &alive)
        : m_rng(std::random_device{}())
        , m_timer(ex)
        , m_socket(socket)
        , m_opts(opts)
        , m_cache(cache)
        , m_destination(destination)
        , m_chains(ex, stopped, mdns_opts, [this](const std::vector<std::byte> &packet) { send(packet, "query send"); })
        , m_mdns_opts(mdns_opts)
        , m_schedule()
        , m_stopped(stopped)
        , m_alive(alive)
    {
    }

    timer_type &timer() noexcept { return m_timer; }
    const monitor_schedule<Clock> &schedule() const noexcept { return m_schedule; }
    monitor_tc_chains<P> &chains() noexcept { return m_chains; }
    const monitor_tc_chains<P> &chains() const noexcept { return m_chains; }

    void watch(dns_name type)
    {
        m_schedule.add_watch(std::move(type), [this] { return initial_query_delay(); });
    }

    void unwatch(const dns_name &type) { m_schedule.remove_watch(type); }

    void reseed_first_queries()
    {
        m_schedule.reseed_first_queries([this] { return initial_query_delay(); });
    }

    // Returns whether a schedule was built.
    bool rebuild_refresh(const dns_name &instance, uint32_t wire_ttl)
    {
        if(!monitor_schedule<Clock>::refreshes(m_opts.mode) || m_mdns_opts.ttl_refresh_thresholds.empty())
            return false;
        m_schedule.rebuild_refresh({instance, dns_type::srv}, wire_ttl, m_mdns_opts, m_rng);
        return true;
    }

    void forget_refresh(const dns_name &instance) { m_schedule.drop_refresh({instance, dns_type::srv}); }

    void arm()
    {
        auto now = Clock::now();
        auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            m_schedule.next_wakeup(m_opts.mode, now) - now);
        if(delay.count() < 0)
            delay = std::chrono::milliseconds{0};

        m_timer.expires_after(delay);
        auto guard = std::weak_ptr<bool>(m_alive);
        m_timer.async_wait([this, guard](std::error_code ec)
        {
            if(ec || !guard.lock())
                return;
            on_tick();
        });
    }

    void cancel()
    {
        m_timer.cancel();
        m_chains.cancel();
    }

    void send_ptr_query(std::string_view svc_type)
    {
        auto known_answers = select_known_answers(m_cache.find(dns_name(svc_type), dns_type::ptr),
                                                  m_mdns_opts.ka_suppression_fraction);
        auto packets = build_dns_query_tc(svc_type, dns_type::ptr, known_answers, m_mdns_opts.max_query_payload);
        if(!packets.empty())
            m_chains.send(std::move(packets));
    }

    void send_instance_queries(std::string_view inst_name)
    {
        auto packet = build_instance_query(inst_name);
        if(packet.empty())
            return;
        send(packet, "instance query send");
    }

private:
    std::mt19937 m_rng;
    timer_type m_timer;
    socket_type &m_socket;
    monitor_options &m_opts;
    record_cache<Clock> &m_cache;
    const endpoint &m_destination;
    monitor_tc_chains<P> m_chains;
    const mdns_options &m_mdns_opts;
    monitor_schedule<Clock> m_schedule;
    const std::atomic<bool> &m_stopped;
    const std::shared_ptr<bool> &m_alive;

    // Expired records are swept on every tick, in every mode.
    void on_tick()
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;
        m_cache.erase_expired();
        auto now = Clock::now();
        for(const auto &type : m_schedule.take_due_watches(m_opts.mode, now, m_mdns_opts))
            send_ptr_query(type);
        for(const auto &instance : m_schedule.take_due_refreshes(m_opts.mode, now))
            send_instance_queries(instance.str());
        arm();
    }

    // RFC 6762 section 5.2: the first query waits a random 20-120 ms by default.
    std::chrono::milliseconds initial_query_delay()
    {
        std::uniform_int_distribution<int32_t> dist(static_cast<int32_t>(m_mdns_opts.response_delay_min.count()),
                                                    static_cast<int32_t>(m_mdns_opts.response_delay_max.count()));
        return std::chrono::milliseconds(dist(m_rng));
    }

    void send(const std::vector<std::byte> &packet, std::string_view context)
    {
        std::error_code ec;
        m_socket.send(m_destination, std::span<const std::byte>(packet), ec);
        if(ec && m_opts.on_error)
            m_opts.on_error(ec, context);
    }
};

}

#endif
