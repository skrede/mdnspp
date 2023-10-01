#include "mdnspp/observer.h"
#include "mdnspp/message_parser.h"

using namespace mdnspp;

observer::observer(std::shared_ptr<log_sink> sink)
    : mdns_base(std::move(sink))
{
}

observer::observer(std::function<void(std::unique_ptr<record_t>)> on_observe)
    : mdns_base(std::make_shared<log_sink>())
    , m_on_observe(std::move(on_observe))
{
}

observer::observer(std::function<void(std::unique_ptr<record_t>)> on_observe, std::shared_ptr<log_sink> sink)
    : mdns_base(std::move(sink))
    , m_on_observe(std::move(on_observe))
{
}

void observer::observe(std::chrono::milliseconds timeout)
{
    m_running = true;
    open_service_sockets();
    listen_while<mdns_socket_listen>(
        [this]() -> bool
        {
            return m_running;
        }, timeout);
    close_sockets();
}

void observer::stop()
{
    mdns_base::stop();
    m_running = false;
}

void observer::callback(socket_t socket, message_buffer &buffer)
{
    service_parser parser(buffer);
    trace() << parser.sender_address() << ": " << parser.entry_type_name() << " " << parser.record_type_name() << " " << parser.name() << " rclass " << buffer.rclass << " ttl " << buffer.ttl;
    if(m_on_observe)
    {
        if(parser.record_type() == MDNS_RECORDTYPE_PTR)
            m_on_observe(std::make_unique<record_ptr_t>(parser.record_parse_ptr()));
        else if(parser.record_type() == MDNS_RECORDTYPE_A)
            m_on_observe(std::make_unique<record_a_t>(parser.record_parse_a()));
        else if(parser.record_type() == MDNS_RECORDTYPE_AAAA)
            m_on_observe(std::make_unique<record_aaaa_t>(parser.record_parse_aaaa()));
        else if(parser.record_type() == MDNS_RECORDTYPE_SRV)
            m_on_observe(std::make_unique<record_srv_t>(parser.record_parse_srv()));
        else if(parser.record_type() == MDNS_RECORDTYPE_TXT)
            for(const auto &txt : parser.record_parse_txt())
                m_on_observe(std::make_unique<record_txt_t>(txt));
    }
}