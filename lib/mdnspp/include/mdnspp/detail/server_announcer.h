#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_ANNOUNCER_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_ANNOUNCER_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_response.h"
#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/server_multicast.h"
#include "mdnspp/detail/server_meta_response.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/policy.h"

#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

// The announcement bursts of RFC 6762 sections 8.3 and 8.4 on the response timer. live_cb follows the
// last announcement after probing.
template <policy_like P>
class server_announcer
{
public:
    using live_callback = move_only_function<void()>;

    server_announcer(server_context<P> &ctx, server_multicast<P> &multicast, live_callback live_cb)
        : m_ctx(ctx)
        , m_live_cb(std::move(live_cb))
        , m_multicast(multicast)
    {
    }

    void start()
    {
        begin_announcing(m_ctx.pa_state);
        send_announce();
    }

    void announce_update()
    {
        m_ctx.pa_state.announce_count = 0;
        send_update_announce();
    }

private:
    server_context<P> &m_ctx;
    live_callback m_live_cb;
    server_multicast<P> &m_multicast;

    void send_announce()
    {
        if(m_ctx.pa_state.state != server_state::announcing) return;
        if(m_ctx.stopped()) return;

        send_announcement();
        if(!advance_announce(m_ctx.pa_state, m_ctx.opts.announce_count))
        {
            m_ctx.pa_state.state = server_state::live;
            m_live_cb();
            return;
        }
        m_ctx.response_timer.expires_after(m_ctx.opts.announce_interval);
        m_ctx.response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_ctx.pa_state.state != server_state::announcing) return;
            if(m_ctx.stopped()) return;
            send_announce();
        });
    }

    void send_update_announce()
    {
        if(m_ctx.stopped()) return;
        if(m_ctx.pa_state.state != server_state::live) return;

        send_announcement();
        if(!advance_announce(m_ctx.pa_state, m_ctx.opts.announce_count))
            return;
        m_ctx.response_timer.expires_after(m_ctx.opts.announce_interval);
        m_ctx.response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_ctx.stopped()) return;
            if(m_ctx.pa_state.state != server_state::live) return;
            send_update_announce();
        });
    }

    void send_announcement()
    {
        m_ctx.validate_addresses();
        auto response = build_dns_response(m_ctx.info, dns_type::any, m_ctx.opts);
        if(!response.empty())
            m_multicast.send_stamped(response, "announcement send");
        send_enumeration_announcements();
    }

    void send_enumeration_announcements()
    {
        uint32_t ttl = wire_ttl(m_ctx.opts.fallback_record_ttl);
        if(m_ctx.opts.respond_to_meta_queries)
        {
            auto pkt = build_meta_query_response(m_ctx.info, ttl);
            if(!pkt.empty())
                m_ctx.send_to(response_mode::multicast, {}, pkt, "announcement send");
        }
        if(!m_ctx.opts.announce_subtypes)
            return;
        for(const auto &sub : m_ctx.info.subtypes)
        {
            auto pkt = build_subtype_response(sub, m_ctx.info, ttl);
            if(!pkt.empty())
                m_ctx.send_to(response_mode::multicast, {}, pkt, "announcement send");
        }
    }
};

}

#endif
