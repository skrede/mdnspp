#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_DISCOVERY_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_DISCOVERY_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_type.h"
#include "mdnspp/query_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/discovery_engine.h"

#include <string>
#include <vector>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp {

template <policy_like P>
class basic_service_discovery : detail::discovery_engine<P>
{
    using base = detail::discovery_engine<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    using record_callback = mdnspp::record_callback;
    using completion_handler = mdnspp::discovery_completion_handler;
    using browse_handler = mdnspp::browse_completion_handler;
    using enumerate_handler = move_only_function<void(std::error_code, std::vector<service_type_info>)>;
    using error_handler = mdnspp::error_handler;

    // Non-copyable and non-movable (recv_loop and timer handlers capture this)
    basic_service_discovery(const basic_service_discovery &) = delete;
    basic_service_discovery &operator=(const basic_service_discovery &) = delete;
    basic_service_discovery(basic_service_discovery &&) = delete;
    basic_service_discovery &operator=(basic_service_discovery &&) = delete;

    ~basic_service_discovery()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard;
        // complete a still-pending handler with operation_canceled instead of
        // silently dropping it.
        this->m_operation.complete_pending(std::make_error_code(std::errc::operation_canceled));
    }

    explicit basic_service_discovery(executor_type ex,
                                     query_options opts = {},
                                     policy_socket_options_t<P> sock_opts = {},
                                     mdns_options mdns_opts = {})
        : base(ex, std::move(opts), std::move(sock_opts), std::move(mdns_opts))
    {
    }

    basic_service_discovery(executor_type ex,
                            query_options opts,
                            policy_socket_options_t<P> sock_opts,
                            mdns_options mdns_opts,
                            std::error_code &ec)
        : base(ex, std::move(opts), std::move(sock_opts), std::move(mdns_opts), ec)
    {
    }

    const timer_type &delay_timer() const noexcept { return this->m_sender.timer(); }
    timer_type &delay_timer() noexcept { return this->m_sender.timer(); }

    void async_discover(std::string_view service_type, completion_handler on_done,
                        response_mode mode = response_mode::multicast)
    {
        if(this->template reject<mdns_record_variant>(this->query_misuse(service_type), on_done))
            return;
        this->m_operation.start_discover(std::move(on_done));
        this->do_query(std::string(service_type), mode);
    }

    void async_browse(std::string_view service_type,
                      browse_handler on_done,
                      response_mode mode = response_mode::multicast)
    {
        if(this->template reject<resolved_service>(this->query_misuse(service_type), on_done))
            return;
        this->m_operation.start_browse(std::move(on_done));
        this->do_query(std::string(service_type), mode);
    }

    void async_enumerate_types(enumerate_handler on_done,
                               response_mode mode = response_mode::multicast)
    {
        if(this->template reject<service_type_info>(this->start_misuse(this->m_operation.active()), on_done))
            return;
        this->m_operation.start_enumerate(std::move(on_done));
        this->do_enumerate(mode);
    }

    void async_discover_subtype(std::string_view service_type,
                                std::string_view subtype_label,
                                completion_handler on_done,
                                response_mode mode = response_mode::multicast)
    {
        auto query_name = std::string(subtype_label) + "._sub." + std::string(service_type);
        async_discover(query_name, std::move(on_done), mode);
    }

    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return this->m_operation.results();
    }

    const std::vector<resolved_service> &services() const noexcept
    {
        return this->m_operation.services();
    }

    void stop()
    {
        base::stop([this]()
        {
            delay_timer().cancel();
            if(this->m_loop)
                this->m_loop->stop();
            this->m_operation.complete_pending(std::make_error_code(std::errc::operation_canceled));
        });
    }
};

}

#endif
