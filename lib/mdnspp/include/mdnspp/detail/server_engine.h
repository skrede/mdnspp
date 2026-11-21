#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_ENGINE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_ENGINE_H

#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/server_prober.h"
#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/server_dispatch.h"
#include "mdnspp/detail/server_validate.h"
#include "mdnspp/detail/server_announcer.h"
#include "mdnspp/detail/server_multicast.h"
#include "mdnspp/detail/server_responder.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/server_tc_queries.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"

#include <span>
#include <atomic>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

template <policy_like P>
class server_engine : protected basic_mdns_peer_base<P>
{
    using base = basic_mdns_peer_base<P>;

protected:
    using completion_handler = server_completion_handler;

    server_engine(typename base::executor_type ex, service_info info, service_options opts,
                  policy_socket_options_t<P> sock_opts, mdns_options mdns_opts)
        : base(ex, sock_opts, std::move(mdns_opts))
        , m_ctx(ex, std::move(info), std::move(opts), extract_interface_binding(sock_opts), this->m_socket,
                this->m_multicast_ep, this->m_mdns_opts, this->m_stopped)
        , m_multicast(m_ctx)
        , m_responder(m_ctx, m_multicast)
        , m_tc(m_ctx, m_multicast)
        , m_announcer(m_ctx, m_multicast, [this] { complete_ready(std::error_code{}); })
        , m_prober(m_ctx, m_multicast, m_announcer, [this](std::error_code reason) { abort_startup(reason); })
        , m_dispatch(m_ctx, m_prober, m_multicast, m_tc, m_responder)
        , m_on_ready()
        , m_on_completion()
        , m_started(false)
    {
        if(auto ec = validate_server_options(m_ctx.info, m_ctx.opts, this->m_mdns_opts))
            throw std::system_error(ec, "basic_service_server options");
    }

    server_engine(typename base::executor_type ex, service_info info, service_options opts,
                  policy_socket_options_t<P> sock_opts, mdns_options mdns_opts, std::error_code &ec)
        : base(ex, sock_opts, std::move(mdns_opts), ec)
        , m_ctx(ex, std::move(info), std::move(opts), extract_interface_binding(sock_opts), this->m_socket,
                this->m_multicast_ep, this->m_mdns_opts, this->m_stopped)
        , m_multicast(m_ctx)
        , m_responder(m_ctx, m_multicast)
        , m_tc(m_ctx, m_multicast)
        , m_announcer(m_ctx, m_multicast, [this] { complete_ready(std::error_code{}); })
        , m_prober(m_ctx, m_multicast, m_announcer, [this](std::error_code reason) { abort_startup(reason); })
        , m_dispatch(m_ctx, m_prober, m_multicast, m_tc, m_responder)
        , m_on_ready()
        , m_on_completion()
        , m_started(false)
    {
        if(!ec)
            ec = validate_server_options(m_ctx.info, m_ctx.opts, this->m_mdns_opts);
    }

    std::error_code claim_start() noexcept
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return std::make_error_code(std::errc::invalid_argument);
        if(m_started.exchange(true, std::memory_order_acq_rel))
            return std::make_error_code(std::errc::operation_in_progress);
        return {};
    }

    // The receive loop starts only after the first probe is scheduled.
    void start(completion_handler on_ready, completion_handler on_done)
    {
        if(on_ready)
            m_on_ready = std::move(on_ready);
        if(on_done)
            m_on_completion = std::move(on_done);
        m_ctx.resolve_auto_addresses();
        this->make_receive_loop(
            infinite_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                m_dispatch.on_packet(meta.sender, data);
                return true;
            },
            [] {},
            [this](std::error_code ec) { m_ctx.report_error(ec, "receive"); });
        m_prober.start_probing();
        this->m_loop->start();
    }

    void shut_down()
    {
        m_multicast.send_goodbye();
        if(m_ctx.pa_state.state == server_state::probing || m_ctx.pa_state.state == server_state::announcing)
            complete_ready(std::make_error_code(std::errc::operation_canceled));
        teardown();
        complete_done(std::error_code{});
    }

    void update(service_info info)
    {
        if(this->m_stopped.load(std::memory_order_acquire)) return;
        bool renamed = info.service_name != m_ctx.info.service_name || info.hostname != m_ctx.info.hostname;
        m_ctx.info = std::move(info);
        m_ctx.resolve_auto_addresses();
        if(renamed)
        {
            m_prober.start_probing();
            return;
        }
        m_announcer.announce_update();
    }

    void cancel_handlers()
    {
        complete_ready(std::make_error_code(std::errc::operation_canceled));
        complete_done(std::make_error_code(std::errc::operation_canceled));
    }

    server_context<P> m_ctx;
    server_multicast<P> m_multicast;
    server_responder<P> m_responder;
    server_tc_queries<P> m_tc;
    server_announcer<P> m_announcer;
    server_prober<P> m_prober;
    server_dispatch<P> m_dispatch;
    completion_handler m_on_ready;
    completion_handler m_on_completion;
    std::atomic<bool> m_started;

private:
    void abort_startup(std::error_code reason)
    {
        if(this->m_stopped.exchange(true, std::memory_order_acq_rel))
            return;
        complete_ready(reason);
        teardown();
        complete_done(std::error_code{});
    }

    void teardown()
    {
        m_ctx.pa_state.state = server_state::stopped;
        m_multicast.drop_pending();
        m_ctx.response_timer.cancel();
        m_ctx.delay_timer.cancel();
        m_ctx.tc_timer.cancel();
        m_tc.clear();
        if(this->m_loop)
            this->m_loop->stop();
    }

    void complete_ready(std::error_code ec)
    {
        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(ec);
    }

    void complete_done(std::error_code ec)
    {
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(ec);
    }
};

}

#endif
