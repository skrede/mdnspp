#include "mdnspp/service_discovery.h"

#include "mdnspp/record_buffer.h"
#include "mdnspp/record_parser.h"

using namespace mdnspp;

service_discovery::service_discovery(params params)
    : mdns_base(params.recv_buf_size)
    , m_timeout(params.timeout)
{
}

service_discovery::service_discovery(std::shared_ptr<log_sink> sink, params params)
    : mdns_base(std::move(sink), params.recv_buf_size)
    , m_timeout(params.timeout)
{
}

service_discovery::service_discovery(std::function<void(std::shared_ptr<record_t>)> on_discover, params params)
    : mdns_base(std::make_shared<log_sink>(), params.recv_buf_size)
    , m_timeout(params.timeout)
    , m_on_discover(std::move(on_discover))
{
}

service_discovery::service_discovery(std::function<void(std::shared_ptr<record_t>)> on_discover, std::shared_ptr<log_sink> sink, params params)
    : mdns_base(std::move(sink), params.recv_buf_size)
    , m_timeout(params.timeout)
    , m_on_discover(std::move(on_discover))
{
}

void service_discovery::discover()
{
    open_client_sockets();
    send(
        [&](index_t soc_idx, socket_t socket)
        {
            if(mdns_discovery_send(socket))
                error() << "Failed to send DNS-SD discovery: " << strerror(errno);
        }
    );

    listen_until_silence<mdns_discovery_recv>(m_timeout);
    close_sockets();
}

void service_discovery::discover(std::vector<record_filter> filters)
{
    m_filters = std::move(filters);
    discover();
}

bool service_discovery::filter_ignore_record(const std::shared_ptr<record_t> &record)
{
    if(record == nullptr)
        return true;
    for(const auto &filter : m_filters)
        if(filter(record))
            return false;
    return true;
}

void service_discovery::callback(socket_t socket, record_buffer &buffer)
{
    record_parser parser(buffer);
    if(parser.record_type() == MDNS_RECORDTYPE_TXT)
    {
        for(const auto &txt : parser.parse_txt())
            if(filter_ignore_record(txt))
                continue;
            else if(m_on_discover)
                m_on_discover(txt);
            else
                info() << *txt;
    }
    else
    {
        std::shared_ptr<record_t> record;
        if(parser.record_type() == MDNS_RECORDTYPE_PTR)
            record = parser.record_parse_ptr();
        else if(parser.record_type() == MDNS_RECORDTYPE_SRV)
            record = parser.record_parse_srv();
        else if(parser.record_type() == MDNS_RECORDTYPE_A)
            record = parser.record_parse_a();
        else if(parser.record_type() == MDNS_RECORDTYPE_AAAA)
            record = parser.record_parse_aaaa();
        else
            debug() << "Encountered unknown record: " << parser;

        if(!filter_ignore_record(record))
        {
            if(m_on_discover)
                m_on_discover(record);
            else
                info() << *record;
        }
    }
}
