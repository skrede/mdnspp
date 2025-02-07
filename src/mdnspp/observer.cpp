#include "mdnspp/observer.h"
#include "mdnspp/record_parser.h"

using namespace mdnspp;

observer::observer(params params)
    : mdns_base(params.recv_buf_size)
    , m_timeout(params.timeout)
    , m_running{false}
{
}

observer::observer(std::shared_ptr<log_sink> sink, params params)
    : mdns_base(std::move(sink), params.recv_buf_size)
    , m_timeout(params.timeout)
    , m_running{false}
{
}

observer::observer(std::function<void(std::shared_ptr<record_t>)> on_observe, params params)
    : mdns_base(std::make_shared<log_sink>(), params.recv_buf_size)
    , m_timeout(params.timeout)
    , m_running{false}
    , m_on_observe(std::move(on_observe))
{
}

observer::observer(std::function<void(std::shared_ptr<record_t>)> on_observe, std::shared_ptr<log_sink> sink, params params)
    : mdns_base(std::move(sink), params.recv_buf_size)
    , m_timeout(params.timeout)
    , m_running{false}
    , m_on_observe(std::move(on_observe))
{
}

void observer::observe()
{
    m_running = true;
    open_service_sockets();
    listen_while<mdns_socket_listen>(
        [this]() -> bool
        {
            return m_running;
        }, m_timeout);
    close_sockets();
}

void observer::observe(std::vector<record_filter> filters)
{
    m_filters = std::move(filters);
    observe();
}

void observer::stop()
{
    mdns_base::stop();
    m_running = false;
}

void observer::callback(socket_t socket, record_buffer &buffer)
{
    record_parser parser(buffer);
    if(parser.record_type() == MDNS_RECORDTYPE_TXT)
        for(const std::shared_ptr<record_txt_t> &txt : parser.parse_txt())
        {
            if(filter_ignore_record(txt))
                continue;
            if(m_on_observe)
                m_on_observe(txt);
            else
                info() << *txt;
        }
    else
    {
        std::shared_ptr<record_t> record = parser.parse();
        if(!filter_ignore_record(record))
        {
            if(m_on_observe)
                m_on_observe(record);
            else
                info() << *record;
        }
    }
}

bool observer::filter_ignore_record(const std::shared_ptr<record_t> &record)
{
    if(record == nullptr)
        return true;
    for(const auto &filter : m_filters)
        if(filter(record))
            return true;
    return false;
}
