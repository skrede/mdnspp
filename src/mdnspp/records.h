#ifndef MDNSPP_RECORDS_H
#define MDNSPP_RECORDS_H

#include <mdns.h>

#include <string>
#include <cstdint>

namespace mdnspp {

struct record_t
{
    uint32_t ttl;
    uint16_t rclass;
    mdns_record_type_t type;
    std::string name;
};

struct record_ptr_t : public record_t
{
    std::string ptr_name;
};

struct record_srv_t : public record_t
{
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    std::string name;
};

struct record_a_t : public record_t
{
    sockaddr_in addr;
};

struct record_aaaa_t : public record_t
{
    sockaddr_in6 addr;
};

struct record_txt_t : public record_t
{
    std::string key;
    std::string value;
};

}

#endif
