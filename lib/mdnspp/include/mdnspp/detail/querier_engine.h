#ifndef HPP_GUARD_MDNSPP_DETAIL_QUERIER_ENGINE_H
#define HPP_GUARD_MDNSPP_DETAIL_QUERIER_ENGINE_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/querier_send.h"
#include "mdnspp/detail/querier_packets.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

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
#include <cstdint>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

template <policy_like P>
class querier_engine : protected basic_mdns_peer_base<P>
{
    using base = basic_mdns_peer_base<P>;

protected:
    querier_engine(typename base::executor_type ex, query_options opts, policy_socket_options_t<P> sock_opts,
                   mdns_options mdns_opts)
        : base(ex, std::move(sock_opts), std::move(mdns_opts))
        , m_query_type(dns_type::none)
        , m_query_mode(response_mode::multicast)
        , m_silence_timeout(opts.silence_timeout)
        , m_sender(ex, this->m_socket, this->multicast_endpoint(), this->m_mdns_opts, this->qu_history(), m_on_error)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        throw_on_error(validate());
    }

    querier_engine(typename base::executor_type ex, query_options opts, policy_socket_options_t<P> sock_opts,
                   mdns_options mdns_opts, std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_query_type(dns_type::none)
        , m_query_mode(response_mode::multicast)
        , m_silence_timeout(opts.silence_timeout)
        , m_sender(ex, this->m_socket, this->multicast_endpoint(), this->m_mdns_opts, this->qu_history(), m_on_error)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        if(!ec)
            ec = validate();
    }

    std::error_code query_misuse(std::string_view name) const
    {
        auto misuse = this->start_misuse(this->m_loop != nullptr);
        if(!misuse && !dns_name::parse(name).has_value())
            misuse = make_error_code(mdns_error::invalid_name);
        return misuse;
    }

    void do_query(std::string qname, dns_type qtype, response_mode mode)
    {
        init_query_state(std::move(qname), qtype, mode);
        this->make_receive_loop(
            m_silence_timeout,
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                return on_packet(meta, data);
            },
            [this]() { fire_completion(); },
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
            });

        if(mode == response_mode::unicast)
            start_unicast_query();
        else
            start_multicast_query();
    }

    dns_type m_query_type;
    response_mode m_query_mode;
    std::chrono::milliseconds m_silence_timeout;
    querier_sender<P> m_sender;
    dns_name m_query_name;
    error_handler m_on_error;
    record_callback m_on_record;
    querier_completion_handler m_on_completion;
    std::vector<mdns_record_variant> m_results;

private:
    std::error_code validate() const noexcept
    {
        if(m_silence_timeout.count() <= 0)
            return std::make_error_code(std::errc::invalid_argument);
        return validate_mdns_options(this->m_mdns_opts);
    }

    void init_query_state(std::string qname, dns_type qtype, response_mode mode)
    {
        m_results.clear();
        m_query_name = dns_name(std::move(qname));
        m_query_type = qtype;
        m_query_mode = mode;
        m_sender.reset();
    }

    bool on_packet(const recv_metadata &meta, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return false;

        auto cdata = std::span<const std::byte>(data.data(), data.size());
        if(!m_sender.sent() && m_query_mode == response_mode::multicast
           && is_duplicate_question(cdata, m_query_name, m_query_type))
            m_sender.suppress();

        return take_relevant_response(cdata, meta.sender, m_query_name, m_on_record, m_results);
    }

    void fire_completion()
    {
        this->m_loop->stop();
        m_sender.timer().cancel();
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{}, m_results);
    }

    void start_unicast_query()
    {
        m_sender.send_now(m_query_name, m_query_type, response_mode::unicast);
        this->m_loop->start();
    }

    void start_multicast_query()
    {
        this->m_loop->start();
        m_sender.send_delayed(m_query_name, m_query_type);
    }
};

}

#endif
