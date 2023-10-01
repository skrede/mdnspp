#include "mdnspp/service_discovery.h"

#include "mdnspp/message_buffer.h"
#include "mdnspp/message_parser.h"

using namespace mdnspp;

service_discovery::service_discovery(std::shared_ptr<log_sink> sink)
    : mdns_base(std::move(sink))
{
}

service_discovery::service_discovery(std::function<void(std::unique_ptr<record_t>)> on_discover)
    : mdns_base(std::make_shared<log_sink>())
    , m_on_discover(std::move(on_discover))
{
}

service_discovery::service_discovery(std::function<void(std::unique_ptr<record_t>)> on_discover, std::shared_ptr<log_sink> sink)
    : mdns_base(std::move(sink))
    , m_on_discover(std::move(on_discover))
{
}

void service_discovery::discover(std::chrono::milliseconds timeout)
{
    open_client_sockets();
    send(
        [&](index_t soc_idx, socket_t socket, void *buffer, size_t capacity)
        {
            if(mdns_discovery_send(socket))
                error() << "Failed to send DNS-SD discovery: " << strerror(errno);
        }
    );

    listen_until_silence<mdns_discovery_recv>(timeout);

    close_sockets();
}

void service_discovery::callback(socket_t socket, message_buffer &buffer)
{
    service_parser parser(buffer);

    auto entry_type = parser.entry_type_name();

    auto entry_str = parser.name();

    if(parser.record_type() == MDNS_RECORDTYPE_PTR)
    {
        auto ptr = parser.record_parse_ptr();
        info() << ptr;
        if(m_on_discover)
            m_on_discover(std::make_unique<record_ptr_t>(ptr));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_SRV)
    {
        auto srv = parser.record_parse_srv();
        info() << srv;
        if(m_on_discover)
            m_on_discover(std::make_unique<record_srv_t>(srv));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_A)
    {
        auto a = parser.record_parse_a();
        info() << a;
        if(m_on_discover)
            m_on_discover(std::make_unique<record_a_t>(a));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_AAAA)
    {
        auto a = parser.record_parse_aaaa();
        info() << a;
        if(m_on_discover)
            m_on_discover(std::make_unique<record_aaaa_t>(a));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_TXT)
    {
        for(const auto &txt : parser.record_parse_txt())
        {
            info() << txt;
            if(m_on_discover)
                m_on_discover(std::make_unique<record_txt_t>(txt));
        }
    }
    else
        debug() << parser.sender_address() << ": " << entry_type << " type " << entry_str << " rclass 0x" << std::hex << parser.record_class() << std::dec << " ttl " << parser.ttl() << " length " << parser.record_length();
}