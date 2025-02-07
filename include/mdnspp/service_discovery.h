#ifndef MDNSPP_SERVICE_DISCOVERY_H
#define MDNSPP_SERVICE_DISCOVERY_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"

namespace mdnspp {

class service_discovery : public mdns_base
{
public:
    struct params
    {
        params(): recv_buf_size(2048), timeout(500)
        {
        }

        uint32_t recv_buf_size;
        std::chrono::milliseconds timeout;
    };

    explicit service_discovery(params p = params());
    explicit service_discovery(std::shared_ptr<log_sink> sink, params p = params());
    explicit service_discovery(std::function<void(std::shared_ptr<record_t> record)> on_discover, params p = params());
    service_discovery(std::function<void(std::shared_ptr<record_t> record)> on_discover, std::shared_ptr<log_sink> sink, params p = params());

    void discover();
    void discover(std::vector<record_filter> filters);

private:
    std::chrono::milliseconds m_timeout;
    std::vector<record_filter> m_filters;
    std::function<void(std::shared_ptr<record_t> record)> m_on_discover;

    bool filter_ignore_record(const std::shared_ptr<record_t> &record);
    void callback(socket_t socket, record_buffer &buffer) override;
};

}

#endif
