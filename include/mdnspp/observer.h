#ifndef MDNSPP_OBSERVER_H
#define MDNSPP_OBSERVER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"

#include <atomic>

namespace mdnspp {

class observer : public mdns_base
{
public:
    struct params
    {
        params(): recv_buf_size(4096), timeout(500)
        {
        }

        uint32_t recv_buf_size;
        std::chrono::milliseconds timeout;
    };

    explicit observer(params p = params());
    explicit observer(std::shared_ptr<log_sink> sink, params p = params());
    explicit observer(std::function<void(std::shared_ptr<record_t> record)> on_observe, params p = params());
    observer(std::function<void(std::shared_ptr<record_t> record)> on_observe, std::shared_ptr<log_sink> sink, params p = params());

    void observe();
    void observe(std::vector<record_filter> filters);

    void stop() override;

private:
    std::atomic<bool> m_running;
    std::chrono::milliseconds m_timeout;
    std::vector<record_filter> m_filters;
    std::function<void(const std::shared_ptr<record_t> &)> m_on_observe;

    void callback(socket_t socket, record_buffer &buffer) override;
    bool filter_ignore_record(const std::shared_ptr<record_t> &record);
};

}

#endif
