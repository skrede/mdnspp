#ifndef MDNSPP_SERVICE_H
#define MDNSPP_SERVICE_H

#include <memory>
#include <string>

namespace mdnspp {

class service
{
    class impl;
public:
    service(const std::string &name, const std::string &hostname, uint16_t port);
    service(service &&) = delete;
    service(const service &) = delete;
    ~service();

    void serve();
    void stop();

    bool isServing();

private:
    std::unique_ptr<service::impl> m_impl;
};

}

#endif
