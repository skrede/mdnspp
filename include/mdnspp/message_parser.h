#ifndef MDNSPP_MESSAGE_PARSER_H
#define MDNSPP_MESSAGE_PARSER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_util.h"

#include "mdnspp/message_buffer.h"

#include <memory>
#include <optional>
#include <vector>

namespace mdnspp {

class message_parser
{
public:
    message_parser(message_buffer &buffer);

    uint32_t ttl() const;
    uint16_t query_id() const;

    const std::string &name();

    const sockaddr &sender() const;
    const std::string &sender_address();

    uint16_t record_type() const;
    std::string record_type_name() const;

    mdns_entry_type entry_type() const;
    std::string entry_type_name() const;

    size_t record_length() const;
    uint16_t record_class() const;

    message_buffer &buffer();

protected:
    std::optional<std::string> m_name;
    std::optional<std::string> m_sender_address;
    message_buffer &m_buffer;

    void set_record_data(record_t &record);
};

class service_parser : public message_parser
{
public:
    using message_parser::message_parser;

    record_ptr_t record_parse_ptr();
    record_srv_t record_parse_srv();
    record_a_t record_parse_a();
    record_aaaa_t record_parse_aaaa();
    std::vector<record_txt_t> record_parse_txt();
};

class client_parser : public message_parser
{
public:
    using message_parser::message_parser;
};

}

#endif