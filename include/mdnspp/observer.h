#ifndef MDNSPP_OBSERVER_H
#define MDNSPP_OBSERVER_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_base.h"

#include <atomic>

namespace mdnspp {

class observer : public mdns_base
{
public:
    observer() = default;
    observer(std::shared_ptr<log_sink> sink);
    observer(std::function<void(std::unique_ptr<record_t> record)> on_observe);
    explicit observer(std::function<void(std::unique_ptr<record_t> record)> on_observe, std::shared_ptr<log_sink> sink);

    void observe(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    void stop() override;

private:
    std::atomic<bool> m_running = {false};
    std::function<void(std::unique_ptr<record_t>)> m_on_observe;

    void callback(socket_t socket, message_buffer &buffer) override;
};

}

#endif
