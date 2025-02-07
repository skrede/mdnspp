#ifndef MDNSPP_RECORD_PARSER_H
#define MDNSPP_RECORD_PARSER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_util.h"
#include "mdnspp/record_buffer.h"

#include <vector>

namespace mdnspp {

class record_parser
{
public:
    explicit record_parser(record_buffer &buffer);

    uint32_t ttl() const;
    uint16_t query_id() const;

    const std::string &name() const;

    const sockaddr &sender() const;
    const std::string &sender_address() const;

    uint16_t record_type() const;
    std::string record_type_name() const;

    mdns_entry_type entry_type() const;
    std::string entry_type_name() const;

    size_t record_length() const;
    uint16_t record_class() const;

    record_buffer &buffer();
    const record_buffer &buffer() const;

    std::shared_ptr<record_t> parse() const;
    std::vector<std::shared_ptr<record_txt_t>> parse_txt() const;

    std::shared_ptr<record_t> record_parse_any() const;
    std::shared_ptr<record_ptr_t> record_parse_ptr() const;
    std::shared_ptr<record_srv_t> record_parse_srv() const;
    std::shared_ptr<record_a_t> record_parse_a() const;
    std::shared_ptr<record_aaaa_t> record_parse_aaaa() const;

protected:
    record_buffer &m_buffer;
    std::string m_name;
    std::string m_sender_address;

    void set_record_data(record_t &record) const;
};

inline std::ostream &operator<<(std::ostream &str, const record_parser &parser)
{
    str << parser.sender_address() << ": " << parser.entry_type_name() << " " << parser.record_type_name() << " "
        << parser.name() << " rclass 0x" << std::hex << parser.record_class() << std::dec << " ttl " << parser.ttl() << " length " << parser.record_length();
    return str;
}

}

#endif
