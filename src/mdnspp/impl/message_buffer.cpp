#include "message_buffer.h"

#include "mdnspp/mdns_util.h"

#include <cstring>

using namespace mdnspp;

message_buffer::message_buffer(const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, mdns_record_type rtype, mdns_class_t rclass, uint32_t ttl,
                               const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length)
    : m_sender(*from)
    , m_addrlen(addrlen)
    , m_entry(entry)
    , m_query_id(query_id)
    , m_rtype(rtype)
    , m_rclass(rclass)
    , m_ttl(ttl)
    , m_size(size)
    , m_name_offset(name_offset)
    , m_name_length(name_length)
    , m_record_offset(record_offset)
    , m_record_length(record_length)
{
    auto *buffer = new char[size];
    memcpy(buffer, data, size);
    m_data.reset(buffer);

    set_name();
    set_sender_address();
}

const std::string &message_buffer::name() const
{
    return m_name;
}

const sockaddr &message_buffer::sender() const
{
    return m_sender;
}

const std::string &message_buffer::sender_address() const
{
    return m_sender_addres;
}

void message_buffer::set_name()
{
    char name_buffer[256];
    mdns_string_t name = mdns_string_extract(m_data.get(), m_size, &m_name_offset, name_buffer, sizeof(name_buffer));
    m_name = std::string(name.str, name.length);
}

void message_buffer::set_sender_address()
{
    char addr_buffer[64];
    mdns_string_t from_addr_str = ip_address_to_string(addr_buffer, sizeof(addr_buffer), &m_sender, m_addrlen);
    m_sender_addres = std::string(from_addr_str.str, from_addr_str.length);
}

mdns_record_type message_buffer::record_type() const
{
    return m_rtype;
}

std::string message_buffer::record_type_name() const
{
    switch(m_rtype)
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
            return "IGNORE";
    }
}

mdns_class_t message_buffer::record_class() const
{
    return MDNS_CLASS_IN;
}

mdns_entry_type message_buffer::entry_type() const
{
    return m_entry;
}

std::string message_buffer::entry_type_name() const
{
    switch(m_entry)
    {
        case MDNS_ENTRYTYPE_QUESTION:
            return "question";
        case MDNS_ENTRYTYPE_ANSWER:
            return "answer";
        case MDNS_ENTRYTYPE_AUTHORITY:
            return "authority";
        default:
            return "additional";
    }
}

record_ptr_t message_buffer::record_parse_ptr()
{
    return record_ptr_t();
}

record_srv_t message_buffer::record_parse_srv()
{
    return record_srv_t();
}

record_a_t message_buffer::record_parse_a()
{
    return record_a_t();
}

record_aaaa_t message_buffer::record_parse_aaaa()
{
    return record_aaaa_t();
}

record_txt_t message_buffer::record_parse_txt()
{
    return record_txt_t();
}
