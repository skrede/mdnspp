#ifndef MDNSPP_MESSAGE_BUFFER_H
#define MDNSPP_MESSAGE_BUFFER_H

#include <mdns.h>

#include <memory>
#include <string>
#include <functional>

namespace mdnspp {

struct message_buffer
{
public:
    message_buffer(const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, mdns_record_type rtype, mdns_class_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length);

    sockaddr m_sender;
    size_t m_addrlen;
    mdns_entry_type_t m_entry;
    uint16_t m_query_id;
    mdns_record_type m_rtype;
    mdns_class_t m_rclass;
    uint32_t m_ttl;
    size_t m_size;
    size_t m_name_offset;
    size_t m_name_length;
    size_t m_record_offset;
    size_t m_record_length;
    const void *m_data;
};

}

#endif
