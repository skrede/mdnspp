#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_MONITOR_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_MONITOR_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/cache_entry.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/record_cache.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/policy_clock.h"
#include "mdnspp/detail/monitor_engine.h"

#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp {

template <policy_like P, typename Clock = detail::policy_clock_t<P>>
class basic_service_monitor : detail::monitor_engine<P, Clock>
{
    using base = detail::monitor_engine<P, Clock>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;

    basic_service_monitor(const basic_service_monitor &) = delete;
    basic_service_monitor &operator=(const basic_service_monitor &) = delete;
    basic_service_monitor(basic_service_monitor &&) = delete;
    basic_service_monitor &operator=(basic_service_monitor &&) = delete;

    explicit basic_service_monitor(executor_type ex,
                                   monitor_options opts = {},
                                   policy_socket_options_t<P> sock_opts = {},
                                   mdns_options mdns_opts = {},
                                   cache_options copts = {})
        : base(ex, std::move(opts), std::move(sock_opts), std::move(mdns_opts), std::move(copts))
    {
    }

    basic_service_monitor(executor_type ex,
                          monitor_options opts,
                          policy_socket_options_t<P> sock_opts,
                          mdns_options mdns_opts,
                          cache_options copts,
                          std::error_code &ec)
        : base(ex, std::move(opts), std::move(sock_opts), std::move(mdns_opts), std::move(copts), ec)
    {
    }

    ~basic_service_monitor()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard;
        // complete a still-pending handler instead of silently dropping it.
        if(auto cb = std::exchange(this->m_on_done, {}); cb)
            cb(std::make_error_code(std::errc::operation_canceled));
    }

    void async_start(monitor_completion_handler on_done = {})
    {
        if(auto misuse = this->start_misuse(static_cast<bool>(this->m_loop)))
        {
            if(on_done)
                this->post_guarded([h = std::move(on_done), misuse]() mutable
                {
                    h(misuse);
                });
            return;
        }
        this->m_on_done = std::move(on_done);
        this->start();
    }

    void stop()
    {
        base::stop([this]()
        {
            this->teardown();
        });
    }

    void watch(std::string_view service_type)
    {
        this->post_guarded([this, svc = std::string(service_type)]() mutable
        {
            this->do_watch(std::move(svc));
        });
    }

    void unwatch(std::string_view service_type)
    {
        this->post_guarded([this, svc = std::string(service_type)]() mutable
        {
            this->do_unwatch(std::move(svc));
        });
    }

    std::vector<resolved_service> services() const
    {
        return this->m_receiver.services();
    }

    void query_service_type(std::string_view service_type)
    {
        this->post_guarded([this, svc = std::string(service_type)]()
        {
            this->m_querier.send_ptr_query(svc);
        });
    }

    void query_service_instance(std::string_view instance_name)
    {
        this->post_guarded([this, inst = std::string(instance_name)]()
        {
            this->m_querier.send_instance_queries(inst);
        });
    }

    void tick_expired_for_test()
    {
        this->m_cache.erase_expired();
    }

    timer_type &scheduler_timer_for_test() noexcept { return this->m_querier.timer(); }

    std::size_t refresh_schedule_count_for_test() const noexcept
    {
        return this->m_querier.schedule().refresh_count();
    }

    std::size_t tc_chain_count_for_test() const noexcept { return this->m_querier.chains().size(); }

    void fire_tc_chains_for_test()
    {
        this->m_querier.chains().fire_for_test();
    }
};

}

#endif
