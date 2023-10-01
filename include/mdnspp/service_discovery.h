#ifndef MDNSPP_SERVICE_DISCOVERY_H
#define MDNSPP_SERVICE_DISCOVERY_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"

namespace mdnspp {

class service_discovery : public mdns_base
{
public:
    service_discovery() = default;
    service_discovery(std::shared_ptr<log_sink> sink);
    service_discovery(std::function<void(std::unique_ptr<record_t> record)> on_discover);
    explicit service_discovery(std::function<void(std::unique_ptr<record_t> record)> on_discover, std::shared_ptr<log_sink> sink);

    void discover(std::chrono::milliseconds timeout = std::chrono::milliseconds(500));

private:
    std::function<void(std::unique_ptr<record_t> record)> m_on_discover;

    void callback(socket_t socket, message_buffer &buffer) override;
};

}

#endif
