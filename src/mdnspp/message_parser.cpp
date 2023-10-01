#include "mdnspp/message_parser.h"
#include "mdnspp/message_parser.h"

using namespace mdnspp;

message_parser::message_parser(message_buffer &buffer)
    : m_buffer(buffer)
{
}

const std::string &message_parser::name()
{
    if(m_name.has_value())
        return m_name.value();
    char name_buffer[256];
    mdns_string_t name = mdns_string_extract(m_buffer.data, m_buffer.size, &m_buffer.name_offset, name_buffer, sizeof(name_buffer));
    m_name.emplace(std::string(name.str, name.length));
    return m_name.value();
}

const sockaddr &message_parser::sender() const
{
    return *m_buffer.from;
}

const std::string &message_parser::sender_address()
{
    if(m_sender_address.has_value())
        return m_sender_address.value();
    m_sender_address = ip_address_to_string(m_buffer.from, m_buffer.addrlen);
    return m_sender_address.value();
}

uint16_t message_parser::record_type() const
{
    return m_buffer.rtype;
}

std::string message_parser::record_type_name() const
{
    switch(m_buffer.rtype)
    {
        case MDNS_RECORDTYPE_A:
            return "A";
        case MDNS_RECORDTYPE_PTR:
            return "PTR";
        case MDNS_RECORDTYPE_TXT:
            return "TXT";
        case MDNS_RECORDTYPE_AAAA:
            return "AAAA";
        case MDNS_RECORDTYPE_SRV:
            return "SRV";
        case MDNS_RECORDTYPE_ANY:
            return "ANY";
        default:
            return "UNKNOWN";
    }
}

size_t message_parser::record_length() const
{
    return m_buffer.record_length;
}

uint16_t message_parser::record_class() const
{
    return m_buffer.rclass;
}

mdns_entry_type message_parser::entry_type() const
{
    return m_buffer.entry;
}

std::string message_parser::entry_type_name() const
{
    switch(m_buffer.entry)
    {
        case MDNS_ENTRYTYPE_QUESTION:
            return "QUESTION";
        case MDNS_ENTRYTYPE_ANSWER:
            return "ANSWER";
        case MDNS_ENTRYTYPE_AUTHORITY:
            return "AUTHORITY";
        default:
            return "ADDITIONAL";
    }
}

void message_parser::set_record_data(record_t &record)
{
    record.rclass = m_buffer.rclass;
    record.name = name();
    record.ttl = m_buffer.ttl;
    record.rtype = m_buffer.rtype;
    record.length = m_buffer.record_length;
    record.sender_address = sender_address();
}

uint32_t message_parser::ttl() const
{
    return m_buffer.ttl;
}

uint16_t message_parser::query_id() const
{
    return m_buffer.query_id;
}

message_buffer &message_parser::buffer()
{
    return m_buffer;
}

record_ptr_t service_parser::record_parse_ptr()
{
    char name_buffer[256];
    mdns_string_t name_str = mdns_record_parse_ptr(m_buffer.data, m_buffer.size, m_buffer.record_offset, m_buffer.record_length, name_buffer, sizeof(name_buffer));
    record_ptr_t ret(m_buffer.entry);
    set_record_data(ret);
    ret.ptr_name = std::string(name_str.str, name_str.length);
    return ret;
}

record_srv_t service_parser::record_parse_srv()
{
    char name_buffer[256];
    mdns_record_srv_t srv = mdns_record_parse_srv(m_buffer.data, m_buffer.size, m_buffer.record_offset, m_buffer.record_length, name_buffer, sizeof(name_buffer));
    record_srv_t ret(m_buffer.entry);
    set_record_data(ret);
    ret.weight = srv.weight;
    ret.port = srv.port;
    ret.priority = srv.priority;
    ret.srv_name = std::string(srv.name.str, srv.name.length);
    return ret;
}

record_a_t service_parser::record_parse_a()
{
    sockaddr_in addr;
    char addr_buffer[1024];
    mdns_record_parse_a(m_buffer.data, m_buffer.size, m_buffer.record_offset, m_buffer.record_length, &addr);
    mdns_string_t addrstr = ipv4_address_to_string(addr_buffer, sizeof(addr_buffer), &addr, sizeof(addr));
    record_a_t ret(m_buffer.entry);
    set_record_data(ret);
    ret.addr = addr;
    ret.address_string = std::string(addrstr.str, addrstr.length);
    return ret;
}

record_aaaa_t service_parser::record_parse_aaaa()
{
    sockaddr_in6 addr;
    char name_buffer[256];
    mdns_record_parse_aaaa(m_buffer.data, m_buffer.size, m_buffer.record_offset, m_buffer.record_length, &addr);
    mdns_string_t addrstr = ipv6_address_to_string(name_buffer, sizeof(name_buffer), &addr, sizeof(addr));
    record_aaaa_t ret(m_buffer.entry);
    set_record_data(ret);
    ret.addr = addr;
    ret.address_string = std::string(addrstr.str, addrstr.length);
    return ret;
}

std::vector<record_txt_t> service_parser::record_parse_txt()
{
    mdns_record_txt_t txt_buffer[128];
    size_t parsed = mdns_record_parse_txt(m_buffer.data, m_buffer.size, m_buffer.record_offset, m_buffer.record_length, txt_buffer, sizeof(txt_buffer) / sizeof(mdns_record_txt_t));
    std::vector<record_txt_t> ret;
    for(size_t itxt = 0; itxt < parsed; ++itxt)
    {
        record_txt_t record(m_buffer.entry);
        set_record_data(record);
        auto &buffer = txt_buffer[itxt];
        record.key = std::string(buffer.key.str, buffer.key.length);
        if(buffer.value.length)
            record.value = std::string(buffer.value.str, buffer.value.length);
        ret.push_back(record);
    }
    return ret;
}