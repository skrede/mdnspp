#include "message_buffer.h"

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
}

size_t message_buffer::address_length() const
{
    return m_addrlen;
}

mdns_entry_type_t message_buffer::entry() const
{
    return m_entry;
}

uint16_t message_buffer::query_id() const
{
    return m_query_id;
}

mdns_record_type message_buffer::rtype() const
{
    return m_rtype;
}

mdns_class_t message_buffer::rclass() const
{
    return m_rclass;
}

uint32_t message_buffer::ttl() const
{
    return m_ttl;
}

const sockaddr &message_buffer::sender() const
{
    return m_sender;
}

size_t message_buffer::size() const
{
    return m_size;
}

size_t message_buffer::name_offset() const
{
    return m_name_offset;
}

size_t message_buffer::name_length() const
{
    return m_name_length;
}

size_t message_buffer::record_offset() const
{
    return m_record_offset;
}

size_t message_buffer::record_length() const
{
    return m_record_length;
}

std::shared_ptr<char[]> message_buffer::data() const
{
    return m_data;
}

std::string message_buffer::entry_type_name() const
{
    switch(m_entry)
    {
        case MDNS_ENTRYTYPE_ANSWER:
            return "answer";
        case MDNS_ENTRYTYPE_AUTHORITY:
            return "authority";
        case MDNS_ENTRYTYPE_ADDITIONAL:
            return "additional";
        default:
            return "question";
    }
}
