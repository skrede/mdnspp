#ifndef HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_ENGINE_H
#define HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_ENGINE_H

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/discovery_packets.h"
#include "mdnspp/detail/discovery_operation.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"
#include "mdnspp/detail/discovery_query_sender.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/query_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"

#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <iterator>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

template <policy_like P>
class discovery_engine : protected basic_mdns_peer_base<P>
{
    using base = basic_mdns_peer_base<P>;

protected:
    discovery_engine(typename base::executor_type ex, query_options opts, policy_socket_options_t<P> sock_opts,
                     mdns_options mdns_opts)
        : base(ex, std::move(sock_opts), std::move(mdns_opts))
        , m_silence_timeout(opts.silence_timeout)
        , m_sender(ex, this->m_socket, this->multicast_endpoint(), this->m_mdns_opts, this->m_stopped,
                   this->qu_history(), m_on_error)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        throw_on_error(validate());
    }

    discovery_engine(typename base::executor_type ex, query_options opts, policy_socket_options_t<P> sock_opts,
                     mdns_options mdns_opts, std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_silence_timeout(opts.silence_timeout)
        , m_sender(ex, this->m_socket, this->multicast_endpoint(), this->m_mdns_opts, this->m_stopped,
                   this->qu_history(), m_on_error)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        if(!ec)
            ec = validate();
    }

    std::error_code query_misuse(std::string_view service_type) const
    {
        auto misuse = this->start_misuse(m_operation.active());
        if(!misuse && !dns_name::parse(service_type).has_value())
            misuse = make_error_code(mdns_error::invalid_name);
        return misuse;
    }

    template <typename Result, typename Handler>
    bool reject(std::error_code misuse, Handler &on_done)
    {
        if(!misuse)
            return false;
        if(on_done)
            this->post_guarded([h = std::move(on_done), misuse]() mutable
            {
                h(misuse, std::vector<Result>{});
            });
        return true;
    }

    void do_query(std::string svc_type, response_mode mode)
    {
        m_operation.results().clear();
        m_service_type = dns_name(std::move(svc_type));

        auto query_bytes = build_dns_query(m_service_type, dns_type::ptr,
                                           std::span<const mdns_record_variant>(m_operation.results()), mode);

        m_sender.send(std::move(query_bytes), mode, "query send");
        start_receiving([this](const recv_metadata &meta, std::span<std::byte> data) -> bool
        {
            return on_query_packet(meta.sender, data);
        });
    }

    void do_enumerate(response_mode mode)
    {
        m_operation.enumerated_types().clear();

        static constexpr std::string_view meta_name = "_services._dns-sd._udp.local";

        auto query_bytes = build_dns_query(meta_name, dns_type::ptr, mode);

        m_sender.send(std::move(query_bytes), mode, "enumerate send");
        start_receiving([this](const recv_metadata &meta, std::span<std::byte> data) -> bool
        {
            return on_enumerate_packet(meta.sender, data);
        });
    }

    std::chrono::milliseconds m_silence_timeout;
    discovery_query_sender<P> m_sender;
    dns_name m_service_type;
    error_handler m_on_error;
    record_callback m_on_record;
    discovery_operation m_operation;

private:
    std::error_code validate() const noexcept
    {
        if(m_silence_timeout.count() <= 0)
            return std::make_error_code(std::errc::invalid_argument);
        return validate_mdns_options(this->m_mdns_opts);
    }

    void start_receiving(typename recv_loop<P>::packet_handler on_packet)
    {
        this->make_receive_loop(
            m_silence_timeout,
            std::move(on_packet),
            [this]()
            {
                this->m_loop->stop();
                m_sender.timer().cancel();
                m_operation.complete_naturally();
            },
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
            });
        this->m_loop->start();
    }

    bool on_query_packet(const endpoint &sender, std::span<std::byte> data)
    {
        auto cdata = std::span<const std::byte>(data.data(), data.size());
        if(!is_response_packet(cdata))
            return false;

        std::vector<mdns_record_variant> batch = collect_records(cdata, sender);
        bool relevant = any_record_named(batch, m_service_type);
        if(relevant)
        {
            if(m_on_record)
            {
                for(const auto &rec : batch)
                    m_on_record(sender, rec);
            }
            auto &results = m_operation.results();
            results.insert(results.end(), std::make_move_iterator(batch.begin()),
                           std::make_move_iterator(batch.end()));
        }
        return relevant;
    }

    bool on_enumerate_packet(const endpoint &sender, std::span<std::byte> data)
    {
        auto cdata = std::span<const std::byte>(data.data(), data.size());
        if(!is_response_packet(cdata))
            return false;

        bool found = false;
        walk_dns_frame(cdata, sender,
            [this, &found](mdns_record_variant rec)
            {
                if(add_enumerated_type(rec, m_operation.enumerated_types()))
                    found = true;
            });
        return found;
    }
};

}

#endif
