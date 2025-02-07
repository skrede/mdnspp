#include "mdnspp/service_server.h"

#include <utility>

#include "mdnspp/log.h"
#include "mdnspp/record_builder.h"
#include "mdnspp/records.h"

#include "mdnspp/record_buffer.h"

using namespace mdnspp;

service_server::service_server(const std::string &instance, const std::string &service_name, params p)
    : mdns_base(p.recv_buf_size)
    , m_send_buf_size(p.send_buf_size)
    , m_hostname(instance)
    , m_service_name(service_name)
    , m_running{false}
    , m_buffer(std::make_unique<char[]>(m_send_buf_size))
    , m_timeout(p.timeout)
{

}

service_server::service_server(const std::string &instance, const std::string &service_name, std::shared_ptr<log_sink> sink, params p)
    : mdns_base(std::move(sink), p.recv_buf_size)
    , m_send_buf_size(p.send_buf_size)
    , m_hostname(instance)
    , m_service_name(service_name)
    , m_running{false}
    , m_buffer(std::make_unique<char[]>(m_send_buf_size))
    , m_timeout(p.timeout)
{
}

bool service_server::is_serving() const
{
    return m_running;
}

void service_server::serve(const std::vector<service_txt> &txt_records)
{
    start(txt_records);
    listen();
}

void service_server::serve(const std::vector<service_txt> &txt_records, const std::function<void()> &socket_open_callback)
{
    start(txt_records);
    if(m_running)
        socket_open_callback();
    listen();
}

void service_server::serve_and_announce(const std::vector<service_txt> &txt_records)
{
    start(txt_records);
    if(m_running)
    {
        announce();
        listen();
    }
}

void service_server::serve_and_announce(const std::vector<service_txt> &txt_records, const std::function<void()> &socket_open_callback)
{
    start(txt_records);
    if(m_running)
    {
        socket_open_callback();
        announce();
        listen();
    }
}

void service_server::announce()
{
    if(!m_running)
        return;
    std::lock_guard<std::mutex> l(m_mutex);
    auto record_ptr = m_builder->mdns_record_ptr();
    auto additional = m_builder->additionals_for(MDNS_RECORDTYPE_PTR);
    send([&](index_t soc_idx, socket_t socket)
        {
            mdns_announce_multicast(socket, m_buffer.get(), m_send_buf_size, record_ptr, nullptr, 0, &additional[0], additional.size());
        }
    );
}

void service_server::stop()
{
    std::lock_guard<std::mutex> l(m_mutex);
    if(!m_running)
        return;
    announce_goodbye();
    close_sockets();
}

void service_server::update_txt_records(const std::vector<service_txt> &txt_records)
{
    std::lock_guard<std::mutex> l(m_mutex);
    m_builder->update_txt_records(txt_records);
}

const std::string &service_server::service_instance_name() const
{
    return m_builder->service_instance();
}

void service_server::start(const std::vector<service_txt> &txt_records)
{
    std::lock_guard<std::mutex> l(m_mutex);
    open_service_sockets();

    auto ipv4 = has_address_ipv4() ? address_ipv4() : std::nullopt;
    auto ipv6 = has_address_ipv4() ? address_ipv6() : std::nullopt;

    m_builder = std::make_shared<record_builder>(m_hostname, m_service_name, txt_records, ipv4, ipv6);

    info() << "mDNS service " << m_hostname << " running on " << m_service_name << ":" << ipv4->sin_port << " with " << socket_count() << " socket" << (socket_count() == 1 ? "" : "s");;

    m_running = true;
}

void service_server::announce_goodbye()
{
    std::lock_guard<std::mutex> l(m_mutex);
    auto record_ptr = m_builder->mdns_record_ptr();
    auto additional = m_builder->additionals_for(MDNS_RECORDTYPE_PTR);

    send([&](index_t soc_idx, socket_t socket)
        {
            mdns_goodbye_multicast(socket, m_buffer.get(), m_send_buf_size, record_ptr, nullptr, 0, &additional[0], additional.size());
        }
    );
}

void service_server::listen()
{
    listen_while<mdns_socket_listen>(
        [this]() -> bool
        {
            return m_running;
        }, m_timeout
    );
}

void service_server::callback(socket_t socket, record_buffer &buffer)
{
    std::lock_guard<std::mutex> l(m_mutex);
    record_parser parser(buffer);

    if(parser.entry_type() != MDNS_ENTRYTYPE_QUESTION || parser.record_type() == MDNS_RECORDTYPE_IGNORE)
        return;

    auto name = parser.name();
    auto addr_str = parser.sender_address();
    auto record_name = parser.record_type_name();
    std::string dns_sd = "_services._dns-sd._udp.local.";

    if(name == dns_sd)
    {
        if((parser.record_type() == MDNS_RECORDTYPE_PTR) || (parser.record_type() == MDNS_RECORDTYPE_ANY))
            serve_dns_sd(socket, parser);
    }
    else if(m_builder->service_name_match(name))
    {
        if((parser.record_type() == MDNS_RECORDTYPE_PTR) || (parser.record_type() == MDNS_RECORDTYPE_ANY))
            serve_ptr(socket, parser);
        else if((parser.record_type() == MDNS_RECORDTYPE_SRV) || (parser.record_type() == MDNS_RECORDTYPE_ANY))
            serve_srv(socket, parser);
        else if(parser.record_type() == MDNS_RECORDTYPE_TXT)
            serve_txt(socket, parser);
    }
    else if(m_builder->hostname_match(name))
    {
        if((parser.record_type() == MDNS_RECORDTYPE_A || parser.record_type() == MDNS_RECORDTYPE_ANY) && has_address_ipv4())
            serve_a(socket, parser);
        else if((parser.record_type() == MDNS_RECORDTYPE_AAAA || parser.record_type() == MDNS_RECORDTYPE_ANY) && has_address_ipv6())
            serve_aaaa(socket, parser);
    }
}

void service_server::serve_dns_sd(socket_t socket, record_parser &parser)
{
    auto name = parser.name();
    auto &buffer = parser.buffer();

    // Answer PTR for "<_service-name>._tcp.local." in the DNS-SD domain with reverse mapping to
    // "<hostname>.<_service-name>._tcp.local."
    auto answer = m_builder->mdns_record_dns_sd(name);

    // Send the answer, unicast or multicast depending on flag in query
    uint16_t unicast = (buffer.rclass & MDNS_UNICAST_RESPONSE);
    debug() << "  --> answer " << name << " (" << (unicast ? "unicast" : "multicast") << ")";

    if(unicast)
        mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answer, nullptr, 0, nullptr, 0);
    else
        mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answer, nullptr, 0, nullptr, 0);
}

void service_server::serve_ptr(socket_t socket, record_parser &parser)
{
    auto name = parser.name();
    auto &buffer = parser.buffer();

    // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
    // "<hostname>.<_service-name>._tcp.local."
    mdns_record_t answer = m_builder->mdns_record_ptr();
    auto additional = m_builder->additionals_for(MDNS_RECORDTYPE_PTR);

    // Send the answer, unicast or multicast depending on flag in query
    uint16_t unicast = (buffer.rclass & MDNS_UNICAST_RESPONSE);
    debug() << "  --> answer " << name << " (" << (unicast ? "unicast" : "multicast") << ")";

    if(unicast)
        mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answer, nullptr, 0, &additional[0], additional.size());
    else
        mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answer, nullptr, 0, &additional[0], additional.size());
}

void service_server::serve_srv(socket_t socket, record_parser &parser)
{
    auto name = parser.name();
    auto &buffer = parser.buffer();

    // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
    // "<hostname>.<_service-name>._tcp.local."
    mdns_record_t answer = m_builder->mdns_record_srv();
    auto additional = m_builder->additionals_for(MDNS_RECORDTYPE_SRV);

    uint16_t unicast = (buffer.rclass & MDNS_UNICAST_RESPONSE);
    debug() << "  --> answer " << name << " port " << answer.data.srv.port << " (" << (unicast ? "unicast" : "multicast") << ")";

    if(unicast)
        mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answer, nullptr, 0, &additional[0], additional.size());
    else
        mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answer, nullptr, 0, &additional[0], additional.size());
}

void service_server::serve_a(socket_t socket, record_parser &parser)
{
    auto name = parser.name();
    auto &buffer = parser.buffer();

    // Answer A records mapping "<hostname>.local." to IPv6 address
    mdns_record_t answer = m_builder->mdns_record_a();
    auto additional = m_builder->additionals_for(MDNS_RECORDTYPE_A);

    uint16_t unicast = (buffer.rclass & MDNS_UNICAST_RESPONSE);
    debug() << "  --> answer " << name << " IPv4 " << m_builder->address_ipv4() << " (" << (unicast ? "unicast" : "multicast") << ")";

    if(unicast)
        mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answer, nullptr, 0, &additional[0], additional.size());
    else
        mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answer, nullptr, 0, &additional[0], additional.size());
}

void service_server::serve_aaaa(socket_t socket, record_parser &parser)
{
    auto name = parser.name();
    auto &buffer = parser.buffer();

    // Answer AAAA records mapping "<hostname>.local." to IPv6 address
    mdns_record_t answer = m_builder->mdns_record_aaaa();
    auto additional = m_builder->additionals_for(MDNS_RECORDTYPE_AAAA);

    uint16_t unicast = (buffer.rclass & MDNS_UNICAST_RESPONSE);
    debug() << "  --> answer " << name << " IPv6 " << m_builder->address_ipv6() << " (" << (unicast ? "unicast" : "multicast") << ")";

    if(unicast)
        mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answer, nullptr, 0, &additional[0], additional.size());
    else
        mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answer, nullptr, 0, &additional[0], additional.size());
}

void service_server::serve_txt(socket_t socket, record_parser &parser)
{
    auto name = parser.name();
    auto &buffer = parser.buffer();
    std::vector<mdns_record_t> answers = m_builder->mdns_record_txts();

    uint16_t unicast = (buffer.rclass & MDNS_UNICAST_RESPONSE);
    debug() << "  --> answer " << name << " IPv6 " << m_builder->address_ipv6() << " (" << (unicast ? "unicast" : "multicast") << ")";

    if(unicast)
    {
        if(answers.size() > 1u)
            mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answers[0], nullptr, 0, &answers[0], answers.size());
        else if(answers.size() == 1u)
            mdns_query_answer_unicast(socket, buffer.from, buffer.addrlen, m_buffer.get(), m_send_buf_size, buffer.query_id, static_cast<mdns_record_type>(buffer.rtype), name.c_str(), name.length(), answers[0], nullptr, 0, nullptr, 0u);
    }
    else
    {
        if(answers.size() > 1u)
            mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answers[0], nullptr, 0, &answers[1], answers.size() - 1u);
        else if(answers.size() == 1u)
            mdns_query_answer_multicast(socket, m_buffer.get(), m_send_buf_size, answers[0], nullptr, 0, nullptr, 0u);
    }
}
