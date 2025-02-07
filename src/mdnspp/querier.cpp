#include "mdnspp/querier.h"

#include "mdnspp/record_parser.h"

using namespace mdnspp;

querier::querier(params p)
    : mdns_base(p.recv_buf_size)
    , m_send_buf_size(p.send_buf_size)
    , m_send_buf(std::make_unique<char[]>(m_send_buf_size))
    , m_timeout(p.timeout)
{
}

querier::querier(std::shared_ptr<log_sink> sink, params p)
    : mdns_base(std::move(sink), p.recv_buf_size)
    , m_send_buf_size(p.send_buf_size)
    , m_send_buf(std::make_unique<char[]>(m_send_buf_size))
    , m_timeout(p.timeout)
{

}

querier::querier(std::function<void(std::shared_ptr<record_t>)> on_response, params p)
    : mdns_base(std::make_shared<log_sink>(), p.recv_buf_size)
    , m_send_buf_size(p.send_buf_size)
    , m_send_buf(std::make_unique<char[]>(m_send_buf_size))
    , m_timeout(p.timeout)
    , m_on_response(std::move(on_response))
{
}

querier::querier(std::function<void(std::shared_ptr<record_t>)> on_response, std::shared_ptr<log_sink> sink, params p)
    : mdns_base(std::move(sink), p.recv_buf_size)
    , m_send_buf_size(p.send_buf_size)
    , m_send_buf(std::make_unique<char[]>(m_send_buf_size))
    , m_timeout(p.timeout)
    , m_on_response(std::move(on_response))
{
}

void querier::inquire(const query_t &request)
{
    mdns_query_t query;
    query.type = request.type;
    query.name = request.name.c_str();
    query.length = request.name.length();
    send_query(&query, 1u);
}

void querier::inquire(const query_t &query, std::vector<record_filter> filters)
{
    m_filters = std::move(filters);
    inquire(query);
}

void querier::inquire(const std::vector<query_t> &request)
{
    std::vector<mdns_query_t> queries;
    for(const auto &req : request)
    {
        mdns_query_t query;
        query.type = req.type;
        query.name = req.name.c_str();
        query.length = req.name.length();
        queries.push_back(query);
    }
    send_query(&queries[0], queries.size());
}

void querier::inquire(const std::vector<query_t> &query, std::vector<record_filter> filters)
{
    m_filters = std::move(filters);
    inquire(query);
}

void querier::send_query(mdns_query_t *query, uint16_t count)
{
    int query_id[32];
    open_client_sockets();

    send(
        [&](index_t soc_idx, socket_t socket)
        {
            query_id[soc_idx] =
                mdns_multiquery_send(socket, query, count, m_send_buf.get(), m_send_buf_size, 0);
            if(query_id[soc_idx] < 0)
                error() << "Failed to send mDNS query: " << strerror(errno);
        }
    );

    debug() << "Listening for mDNS query responses";
    listen_until_silence(
        [query_id](index_t soc_idx, socket_t socket, void *buffer, size_t capacity, mdns_record_callback_fn callback, void *user_data)
        -> size_t
        {
            return mdns_query_recv(socket, buffer, capacity, callback, user_data, query_id[soc_idx]);
        }, m_timeout
    );

    close_sockets();
}

void querier::send_query(mdns_query_t *query, uint16_t count, std::vector<record_filter> filters)
{
    m_filters = std::move(filters);
    send_query(query, count);
}

bool querier::filter_ignore_record(const std::shared_ptr<record_t> &record)
{
    if(record == nullptr)
        return true;
    for(const auto &filter : m_filters)
        if(filter(record))
            return true;
    return false;
}

void querier::callback(socket_t socket, record_buffer &buffer)
{
    record_parser parser(buffer);
    if(parser.record_type() == MDNS_RECORDTYPE_TXT)
    {
        for(const auto &txt : parser.parse_txt())
        {
            if(m_on_response)
                m_on_response(txt);
            else
                info() << *txt;
        }
    }
    else
    {
        std::shared_ptr<record_t> record = parser.parse();
        if(!filter_ignore_record(record))
        {
            if(m_on_response)
                m_on_response(record);
            else
                info() << *record;
        }
        else
            debug() << "Encountered unknown record: " << parser;
    }
}
