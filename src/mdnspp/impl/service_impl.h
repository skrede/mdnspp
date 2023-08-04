#ifndef MDNSPP_SERVICE_IMPL_H
#define MDNSPP_SERVICE_IMPL_H

// Provide a mDNS service, answering incoming DNS-SD and mDNS queries

#include "mdnspp/service.h"

#include "mdnspp/impl/mdns_base.h"
#include "mdnspp/impl/services.h"

#include <mutex>
#include <atomic>

namespace mdnspp {

class service::impl : public mdns_base
{
public:
    impl(const std::string &hostname, const std::string &service_name, uint16_t port);

    bool isServing() const;

    void serve();
    void stop();

private:
    uint16_t m_port;
    std::string m_hostname;
    std::string m_service_name;
    service_t service;
    records_t m_records;
    std::mutex m_mutex;
    std::atomic<bool> m_running;
    void *buffer;

    void start(std::string &hostname, std::string service_name);
    void announceService();
    void announceGoodbye();
    void listen();

    int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                 uint16_t query_id, uint16_t rtype_n, uint16_t rclass, uint32_t ttl, const void *data,
                 size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                 size_t record_length) override;
};

}

#endif
