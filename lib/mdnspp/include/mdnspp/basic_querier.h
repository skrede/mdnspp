#ifndef HPP_GUARD_MDNSPP_BASIC_QUERIER_H
#define HPP_GUARD_MDNSPP_BASIC_QUERIER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/query_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/querier_engine.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp {

template <policy_like P>
class basic_querier : detail::querier_engine<P>
{
    using base = detail::querier_engine<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    using record_callback = mdnspp::record_callback;
    using completion_handler = mdnspp::querier_completion_handler;
    using error_handler = mdnspp::error_handler;

    // Non-copyable and non-movable (recv_loop and timer handlers capture this)
    basic_querier(const basic_querier &) = delete;
    basic_querier &operator=(const basic_querier &) = delete;
    basic_querier(basic_querier &&) = delete;
    basic_querier &operator=(basic_querier &&) = delete;

    ~basic_querier()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard; complete a still-pending handler with
        // operation_canceled instead of silently dropping it.
        if(auto h = std::exchange(this->m_on_completion, nullptr); h)
            h(std::make_error_code(std::errc::operation_canceled), std::move(this->m_results));
    }

    explicit basic_querier(executor_type ex, query_options opts = {}, policy_socket_options_t<P> sock_opts = {},
                           mdns_options mdns_opts = {})
        : base(ex, std::move(opts), std::move(sock_opts), std::move(mdns_opts))
    {
    }

    basic_querier(executor_type ex, query_options opts, policy_socket_options_t<P> sock_opts, mdns_options mdns_opts,
                  std::error_code &ec)
        : base(ex, std::move(opts), std::move(sock_opts), std::move(mdns_opts), ec)
    {
    }

    const timer_type &delay_timer() const noexcept { return this->m_sender.timer(); }
    timer_type &delay_timer() noexcept { return this->m_sender.timer(); }

    void async_query(std::string_view name, dns_type qtype, completion_handler on_done,
                     response_mode mode = response_mode::multicast)
    {
        auto misuse = this->query_misuse(name);
        if(misuse)
        {
            if(on_done)
                this->post_guarded([h = std::move(on_done), misuse]() mutable
                {
                    h(misuse, std::vector<mdns_record_variant>{});
                });
            return;
        }
        if(on_done)
            this->m_on_completion = std::move(on_done);
        this->do_query(std::string(name), qtype, mode);
    }

    const std::vector<mdns_record_variant> &results() const noexcept
    {
        return this->m_results;
    }

    void stop()
    {
        base::stop([this]()
        {
            this->m_sender.timer().cancel();

            if(this->m_loop)
            {
                this->m_loop->stop();
                if(auto h = std::exchange(this->m_on_completion, nullptr); h)
                    h(std::make_error_code(std::errc::operation_canceled), this->m_results);
            }
        });
    }
};

}

#endif
