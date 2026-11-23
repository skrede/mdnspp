#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_engine.h"
#include "mdnspp/detail/sibling_records.h"

#include <memory>
#include <cassert>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp {

template <policy_like P>
class basic_service_server : detail::server_engine<P>
{
    using base = detail::server_engine<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;

    using query_callback = move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)>;
    using completion_handler = mdnspp::server_completion_handler;

    basic_service_server(const basic_service_server &) = delete;
    basic_service_server &operator=(const basic_service_server &) = delete;
    basic_service_server(basic_service_server &&) = delete;
    basic_service_server &operator=(basic_service_server &&) = delete;

    // The receive loop closes before the members die. The teardown stop() posts is dropped by the expired
    // alive guard, so the still-pending handlers complete here.
    ~basic_service_server()
    {
        this->m_alive.reset();
        if(this->m_loop)
            this->m_loop->stop();
        stop();
        this->m_lifecycle.cancel();
    }

    explicit basic_service_server(executor_type ex, service_info info,
                                  service_options opts = {},
                                  policy_socket_options_t<P> sock_opts = {},
                                  mdns_options mdns_opts = {})
        : basic_service_server(ex, std::move(info), std::move(opts), std::move(sock_opts), std::move(mdns_opts),
                               nullptr, 0)
    {
    }

    basic_service_server(executor_type ex, service_info info, service_options opts,
                         policy_socket_options_t<P> sock_opts, mdns_options mdns_opts,
                         std::shared_ptr<detail::sibling_records> siblings, std::size_t element)
        : base(ex, std::move(info), std::move(opts), std::move(sock_opts), std::move(mdns_opts), std::move(siblings),
               element)
    {
    }

    basic_service_server(executor_type ex, service_info info,
                         service_options opts, policy_socket_options_t<P> sock_opts,
                         mdns_options mdns_opts, std::error_code &ec)
        : basic_service_server(ex, std::move(info), std::move(opts), std::move(sock_opts), std::move(mdns_opts),
                               nullptr, 0, ec)
    {
    }

    basic_service_server(executor_type ex, service_info info, service_options opts,
                         policy_socket_options_t<P> sock_opts, mdns_options mdns_opts,
                         std::shared_ptr<detail::sibling_records> siblings, std::size_t element, std::error_code &ec)
        : base(ex, std::move(info), std::move(opts), std::move(sock_opts), std::move(mdns_opts), std::move(siblings),
               element, ec)
    {
    }

    void async_start(completion_handler on_ready = {}, completion_handler on_done = {})
    {
        if(auto misuse = this->m_lifecycle.claim_start(this->m_stopped))
        {
            if(on_ready)
                this->post_guarded([h = std::move(on_ready), misuse]() mutable
                {
                    h(misuse);
                });
            return;
        }
        this->start(std::move(on_ready), std::move(on_done));
    }

    // service_info is written on the executor (updates, conflict renames), so the goodbye is built there.
    void stop()
    {
        base::stop([this]()
        {
            this->shut_down();
        });
    }

    void update_service_info(service_info new_info)
    {
        assert(!this->m_stopped.load(std::memory_order_acquire));
        this->post_guarded([this, info = std::move(new_info)]() mutable
        {
            this->update(std::move(info));
        });
    }

    const timer_type &timer() const noexcept { return this->m_ctx.response_timer; }
    timer_type &timer() noexcept { return this->m_ctx.response_timer; }
    const timer_type &delay_timer() const noexcept { return this->m_ctx.delay_timer; }
    timer_type &delay_timer() noexcept { return this->m_ctx.delay_timer; }
    const timer_type &tc_timer() const noexcept { return this->m_ctx.tc_timer; }
    timer_type &tc_timer() noexcept { return this->m_ctx.tc_timer; }
    const timer_type &recv_timer() const noexcept { return base::timer(); }
    timer_type &recv_timer() noexcept { return base::timer(); }
};

}

#endif
