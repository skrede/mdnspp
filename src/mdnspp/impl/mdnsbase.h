#ifndef MDNSPP_MDNSBASE_H
#define MDNSPP_MDNSBASE_H

#include "mdnspp/mdns_util.h"

#include <signal.h>

namespace mdnspp {

class MDNSBase
{
public:
    MDNSBase();
    ~MDNSBase();

protected:
    int sockets[32];
    int num_sockets;
    size_t capacity = 2048;
    void *buffer;
    char *service_name_buffer;
    volatile sig_atomic_t running = 1;
    static mdns_record_txt_t txtbuffer[128];

    sockaddr_in service_address_ipv4;
    sockaddr_in6 service_address_ipv6;

};

}

#endif
