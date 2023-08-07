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
    , m_data(data)
{
}