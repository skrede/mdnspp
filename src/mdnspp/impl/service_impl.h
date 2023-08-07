#ifndef MDNSPP_SERVICE_IMPL_H
#define MDNSPP_SERVICE_IMPL_H

// Provide a mDNS service, answering incoming DNS-SD and mDNS queries

#include "mdnspp/service.h"
#include "mdnspp/services.h"

#include "mdnspp/impl/mdns_base.h"

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

    void start(std::string hostname, std::string service_name);
    void announceService();
    void announceGoodbye();
    void listen();

    void callback(socket_t socket, message_buffer &buffer) override;
};

}

#endif
