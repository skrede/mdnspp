#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_ENGINE_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_ENGINE_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/monitor_loss.h"
#include "mdnspp/detail/monitor_querier.h"
#include "mdnspp/detail/monitor_receiver.h"
#include "mdnspp/detail/monitor_resolver.h"
#include "mdnspp/detail/monitor_instances.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include "mdnspp/policy.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/cache_entry.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/record_cache.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/monitor_options.h"

#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

template <policy_like P, typename Clock>
class monitor_engine : protected basic_mdns_peer_base<P>
{
    using base = basic_mdns_peer_base<P>;

protected:
    monitor_engine(typename base::executor_type ex, monitor_options opts, policy_socket_options_t<P> sock_opts,
                   mdns_options mdns_opts, cache_options copts)
        : base(ex, std::move(sock_opts), std::move(mdns_opts))
        , m_opts(std::move(opts))
        , m_on_done()
        , m_cache_opts(std::move(copts))
        , m_cache(make_cache_options())
        , m_instances()
        , m_resolver(m_instances, m_opts, [this] { m_receiver.publish(); }, refresh_hook())
        , m_loss(m_instances, m_opts, [this] { m_receiver.publish(); }, forget_hook())
        , m_querier(ex, this->m_socket, this->m_multicast_ep, m_cache, m_opts, this->m_mdns_opts, this->m_stopped,
                    this->m_alive)
        , m_receiver(m_cache, m_instances, m_querier.schedule(), m_resolver)
    {
        throw_on_error(validate());
    }

    monitor_engine(typename base::executor_type ex, monitor_options opts, policy_socket_options_t<P> sock_opts,
                   mdns_options mdns_opts, cache_options copts, std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_opts(std::move(opts))
        , m_on_done()
        , m_cache_opts(std::move(copts))
        , m_cache(make_cache_options())
        , m_instances()
        , m_resolver(m_instances, m_opts, [this] { m_receiver.publish(); }, refresh_hook())
        , m_loss(m_instances, m_opts, [this] { m_receiver.publish(); }, forget_hook())
        , m_querier(ex, this->m_socket, this->m_multicast_ep, m_cache, m_opts, this->m_mdns_opts, this->m_stopped,
                    this->m_alive)
        , m_receiver(m_cache, m_instances, m_querier.schedule(), m_resolver)
    {
        if(!ec)
            ec = validate();
    }

    // The first-query deadlines are re-seeded before the loop exists; the monitor has no silence
    // semantics and runs until stop().
    void start()
    {
        m_querier.reseed_first_queries();
        this->make_receive_loop(
            infinite_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                return m_receiver.handle_packet(meta.sender, data);
            },
            [] {},
            [this](std::error_code ec)
            {
                if(m_opts.on_error)
                    m_opts.on_error(ec, "receive");
            });
        this->m_loop->start();
        m_querier.arm();
    }

    void teardown()
    {
        m_querier.cancel();
        if(this->m_loop)
            this->m_loop->stop();
        if(m_on_done)
        {
            auto cb = std::exchange(m_on_done, {});
            cb(std::error_code{});
        }
    }

    void do_watch(std::string svc_type)
    {
        m_querier.watch(dns_name(std::move(svc_type)));
        if(this->m_loop)
            m_querier.arm();
    }

    void do_unwatch(std::string svc_type)
    {
        dns_name type(std::move(svc_type));
        if(!m_querier.schedule().watching(type))
            return;
        m_loss.drop_type(type);
        m_querier.unwatch(type);
        m_receiver.publish();
    }

    monitor_options m_opts;
    monitor_completion_handler m_on_done;
    cache_options m_cache_opts;
    record_cache<Clock> m_cache;
    monitor_instances m_instances;
    monitor_resolver m_resolver;
    monitor_loss m_loss;
    monitor_querier<P, Clock> m_querier;
    monitor_receiver<Clock> m_receiver;

private:
    // Moves from m_cache_opts once, leaving goodbye_grace readable for validate(). An invalid
    // goodbye_grace is clamped so the cache can always be constructed; validate() reports it.
    cache_options make_cache_options()
    {
        cache_options copts = std::move(m_cache_opts);
        if(copts.goodbye_grace.count() <= 0)
            copts.goodbye_grace = std::chrono::seconds(1);
        copts.on_expired = [this](std::vector<cache_entry> expired)
        {
            m_loss.expire(std::move(expired));
        };
        return copts;
    }

    std::error_code validate() const noexcept
    {
        if(m_cache_opts.goodbye_grace.count() <= 0)
            return std::make_error_code(std::errc::invalid_argument);
        return validate_mdns_options(this->m_mdns_opts);
    }

    // A running monitor re-arms so that a long backoff deadline does not sleep past the new fire point.
    monitor_resolver::refresh_callback refresh_hook()
    {
        return [this](const dns_name &instance, uint32_t wire_ttl)
        {
            if(m_querier.rebuild_refresh(instance, wire_ttl) && this->m_loop)
                m_querier.arm();
        };
    }

    monitor_loss::forget_callback forget_hook()
    {
        return [this](const dns_name &instance) { m_querier.forget_refresh(instance); };
    }
};

}

#endif
