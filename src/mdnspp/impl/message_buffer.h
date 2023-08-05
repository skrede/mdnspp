#ifndef MDNSPP_MESSAGEPARSER_H
#define MDNSPP_MESSAGEPARSER_H

#include <mdns.h>

#include <memory>
#include <string>

namespace mdnspp {

class message_buffer
{
public:
    message_buffer(const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, mdns_record_type rtype, mdns_class_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length);

    const std::string &name() const;

    const sockaddr &sender() const;
    const std::string &sender_address() const;

    mdns_record_type record_type() const;
    std::string record_type_name() const;

    mdns_entry_type entry_type() const;
    std::string entry_type_name() const;

    mdns_class_t record_class() const;

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
    std::string m_name;
    std::string m_sender_addres;
    std::unique_ptr<char[]> m_data;

    void set_name();
    void set_sender_address();
};

}

#endif
