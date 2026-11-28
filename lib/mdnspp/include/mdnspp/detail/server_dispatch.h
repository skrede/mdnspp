#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_DISPATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_DISPATCH_H

#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/server_prober.h"
#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/server_multicast.h"
#include "mdnspp/detail/server_responder.h"
#include "mdnspp/detail/server_tc_queries.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

template <policy_like P>
class server_dispatch
{
public:
    server_dispatch(server_context<P> &ctx, server_prober<P> &prober, server_multicast<P> &multicast,
                    server_tc_queries<P> &tc, server_responder<P> &responder)
        : m_ctx(ctx)
        , m_prober(prober)
        , m_tc(tc)
        , m_multicast(multicast)
        , m_responder(responder)
    {
    }

    void on_packet(const endpoint &sender, std::span<std::byte> data)
    {
        if(m_ctx.stopped())
            return;

        auto cdata = std::span<const std::byte>(data.data(), data.size());
        auto state = m_ctx.pa_state.state;
        if(state == server_state::probing)
        {
            m_prober.on_probing_packet(cdata);
            return;
        }
        if((state != server_state::live && state != server_state::announcing) || data.size() < 12)
            return;

        uint16_t flags = read_u16_be(data.data() + 2);
        if((flags & 0x8000) != 0)
        {
            on_response(cdata);
            return;
        }

        // Queries are not answered while announcing.
        if(state == server_state::live)
            on_query(sender, cdata, flags);
    }

private:
    server_context<P> &m_ctx;
    server_prober<P> &m_prober;
    server_tc_queries<P> &m_tc;
    server_multicast<P> &m_multicast;
    server_responder<P> &m_responder;

    // RFC 6762 sections 9 and 7.4: the conflict screen runs first and ends the handling on a conflict.
    void on_response(std::span<const std::byte> cdata)
    {
        auto records = parse_answer_records(cdata);
        if(!m_prober.screen(records))
            m_multicast.observe(records);
    }

    void on_query(const endpoint &sender, std::span<const std::byte> cdata, uint16_t flags)
    {
        if((flags & 0x0200) != 0)
        {
            m_tc.accumulate(sender, cdata);
            return;
        }
        if(m_tc.merge_final(sender, cdata, read_u16_be(cdata.data() + 4)))
            return;
        m_responder.answer(sender, cdata);
    }
};

}

#endif
