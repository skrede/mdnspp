#include "mdnspp/querier.h"

#include "mdnspp/message_parser.h"

using namespace mdnspp;

querier::querier(std::shared_ptr<log_sink> sink)
    : mdns_base(std::move(sink))
{

}

querier::querier(std::function<void(std::unique_ptr<record_t>)> on_response)
    : mdns_base(std::make_shared<log_sink>())
    , m_on_response(std::move(on_response))
{
}

querier::querier(std::function<void(std::unique_ptr<record_t>)> on_response, std::shared_ptr<log_sink> sink)
    : mdns_base(std::move(sink))
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

void querier::send_query(mdns_query_t *query, uint16_t count)
{
    int query_id[32];
    open_client_sockets();

    for(size_t iq = 0; iq < count; ++iq)
        debug() << "Query " << query[iq].name << " for " << record_type(query[iq].type) << " records";
    send(
        [&](index_t soc_idx, socket_t socket, void *buffer, size_t capacity)
        {
            query_id[soc_idx] =
                mdns_multiquery_send(socket, query, count, buffer, capacity, 0);
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
        }, std::chrono::milliseconds(5000)
    );

    close_sockets();
}

void querier::callback(socket_t socket, message_buffer &buffer)
{
    service_parser parser(buffer);

    auto name = parser.name();
    auto addr_str = parser.sender_address();
    auto record_name = parser.record_type_name();

    if(parser.record_type() == MDNS_RECORDTYPE_PTR)
    {
        auto ptr = parser.record_parse_ptr();
        info() << ptr;
        if(m_on_response)
            m_on_response(std::make_unique<record_t>(ptr));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_SRV)
    {
        auto srv = parser.record_parse_srv();
        info() << srv;
        if(m_on_response)
            m_on_response(std::make_unique<record_t>(srv));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_A)
    {
        auto a = parser.record_parse_a();
        info() << a;
        if(m_on_response)
            m_on_response(std::make_unique<record_t>(a));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_AAAA)
    {
        auto aaaa = parser.record_parse_aaaa();
        info() << aaaa;
        if(m_on_response)
            m_on_response(std::make_unique<record_t>(aaaa));
    }
    else if(parser.record_type() == MDNS_RECORDTYPE_TXT)
    {
        for(const auto &txt : parser.record_parse_txt())
        {
            info() << txt;
            if(m_on_response)
                m_on_response(std::make_unique<record_t>(txt));
        }
    }
    else
        info() << parser.sender_address() << ": " << parser.entry_type_name() << " type " << parser.record_type_name() << " " << std::hex << buffer.rtype << std::dec << " rclass " << buffer.rclass << " ttl " << buffer.ttl << " length " << buffer.record_length;
}