#ifndef MDNSPP_SERVICE_IMPL_H
#define MDNSPP_SERVICE_IMPL_H

#include "mdnspp/service.h"

#include "mdnspp/impl/mdnsbase.h"

namespace mdnspp {

int service_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                     uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                     size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                     size_t record_length, void *user_data);

typedef struct
{
    mdns_string_t service;
    mdns_string_t hostname;
    mdns_string_t service_instance;
    mdns_string_t hostname_qualified;
    sockaddr_in address_ipv4;
    sockaddr_in6 address_ipv6;
    uint16_t port;
    mdns_record_t record_ptr;
    mdns_record_t record_srv;
    mdns_record_t record_a;
    mdns_record_t record_aaaa;
    mdns_record_t txt_record[2];
} service_t;

class Service::Impl : public MDNSBase
{
public:
    int serve(const char *hostname, const char *service_name, int service_port);
    void stop();

    bool isServing() const;

private:
    service_t service;

    int start(const char *hostname, const char *service_name, int service_port);
    int listen();
};

}

#endif
