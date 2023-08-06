#ifndef MDNSPP_SERVICES_H
#define MDNSPP_SERVICES_H

#include <string>

#include <mdns.h>

namespace mdnspp {

struct service_t
{
    mdns_string_t name;
    mdns_string_t hostname;
    mdns_string_t service_instance;
    mdns_string_t hostname_qualified;
    sockaddr_in address_ipv4;
    sockaddr_in6 address_ipv6;
    uint16_t port;
};

struct records_t
{
    mdns_record_t record_ptr;
    mdns_record_t record_srv;
    mdns_record_t record_a;
    mdns_record_t record_aaaa;
    mdns_record_t txt_record[2];
};

void default_records(const service_t &service, mdnspp::records_t &records);

}

#endif
