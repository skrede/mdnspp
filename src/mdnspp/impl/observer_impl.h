#ifndef MDNSPP_OBSERVER_IMPL_H
#define MDNSPP_OBSERVER_IMPL_H

// Dump all incoming mDNS queries and answers

#include "mdnspp/observer.h"

#include "mdnspp/impl/mdnsbase.h"

#include <atomic>

namespace mdnspp {

class Observer::Impl : public MDNSBase
{
public:
    int dump_mdns();

    void stop();

    int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) override;

private:
    std::atomic<bool> running;
};

}

#endif
