#ifndef MDNSPP_RECORD_BUFFER_H
#define MDNSPP_RECORD_BUFFER_H

#include <mdns.h>

namespace mdnspp {

struct record_buffer
{
public:
    record_buffer(const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, mdns_record_type rtype, uint16_t rclass,
                  uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length)
        : ttl(ttl)
        , rtype(static_cast<mdns_record_type>(rtype))
        , rclass(rclass)
        , query_id(query_id)
        , data(data)
        , from(from)
        , entry(entry)
        , size(size)
        , addrlen(addrlen)
        , name_offset(name_offset)
        , name_length(name_length)
        , record_offset(record_offset)
        , record_length(record_length)
    {
    }

    record_buffer(record_buffer &&) = delete;
    record_buffer(const record_buffer &) = delete;

    const uint32_t ttl;
    const mdns_record_type rtype;
    const uint16_t rclass;
    const uint16_t query_id;
    const void *data;
    const sockaddr *from;
    const mdns_entry_type_t entry;
    const size_t size;
    const size_t addrlen;
    size_t name_offset;
    const size_t name_length;
    const size_t record_offset;
    const size_t record_length;
};

}

#endif
