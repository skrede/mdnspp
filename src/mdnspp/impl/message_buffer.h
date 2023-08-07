#ifndef MDNSPP_MESSAGE_BUFFER_H
#define MDNSPP_MESSAGE_BUFFER_H

#include <mdns.h>

#include <memory>
#include <string>
#include <functional>

namespace mdnspp {

class message_buffer
{
public:
    message_buffer(const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, mdns_record_type rtype, mdns_class_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length);

    uint32_t ttl() const;
    uint16_t query_id() const;
    size_t name_offset() const;
    size_t name_length() const;
    size_t record_offset() const;
    size_t record_length() const;
    size_t address_length() const;

    mdns_class_t rclass() const;
    mdns_record_type rtype() const;
    mdns_entry_type_t entry() const;
    std::string entry_type_name() const;

    const sockaddr &sender() const;

    size_t size() const;
    std::shared_ptr<char[]> data() const;

private:
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
    std::shared_ptr<char[]> m_data;
};

}

#endif
