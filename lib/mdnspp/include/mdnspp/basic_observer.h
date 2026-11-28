#ifndef HPP_GUARD_MDNSPP_BASIC_OBSERVER_H
#define HPP_GUARD_MDNSPP_BASIC_OBSERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/observer_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
#include <chrono>
#include <utility>
#include <system_error>

namespace mdnspp {

template <policy_like P>
class basic_observer : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    using record_callback = mdnspp::record_callback;
    using completion_handler = mdnspp::observer_completion_handler;
    using error_handler = mdnspp::error_handler;

    // Non-copyable and non-movable (recv_loop handlers capture this)
    basic_observer(const basic_observer &) = delete;
    basic_observer &operator=(const basic_observer &) = delete;
    basic_observer(basic_observer &&) = delete;
    basic_observer &operator=(basic_observer &&) = delete;

    ~basic_observer()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard;
        // complete a still-pending handler instead of silently dropping it.
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::make_error_code(std::errc::operation_canceled));
    }

    explicit basic_observer(executor_type ex, observer_options opts = {},
                            policy_socket_options_t<P> sock_opts = {},
                            mdns_options mdns_opts = {})
        : base(ex, std::move(sock_opts), std::move(mdns_opts))
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        detail::throw_on_error(detail::validate_mdns_options(this->m_mdns_opts));
    }

    basic_observer(executor_type ex, observer_options opts,
                   policy_socket_options_t<P> sock_opts, mdns_options mdns_opts,
                   std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        if(!ec)
            ec = detail::validate_mdns_options(this->m_mdns_opts);
    }

    void async_observe(completion_handler on_done = {})
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
        if(on_done)
            m_on_completion = std::move(on_done);
        do_observe();
    }

    // Stops the loop without destroying it: stop() may run inside the loop's own callback chain,
    // which the destructor is never reached from.
    void stop()
    {
        base::stop([this]()
        {
            if(this->m_loop)
                this->m_loop->stop();

            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::make_error_code(std::errc::operation_canceled));
        });
    }

private:
    void do_observe()
    {
        this->make_receive_loop(
            detail::infinite_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                on_packet(meta.sender, data);
                return true;
            },
            []() {},
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
            });

        this->m_loop->start();
    }

    void on_packet(const endpoint &sender, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        detail::walk_dns_frame(
            std::span<const std::byte>(data.data(), data.size()),
            sender,
            [this, sender](mdns_record_variant rec)
            {
                if(!this->m_stopped.load(std::memory_order_acquire) && m_on_record)
                    m_on_record(sender, rec);
            });
    }

    error_handler m_on_error;
    record_callback m_on_record;
    completion_handler m_on_completion;
};

}

#endif
