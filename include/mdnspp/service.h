#ifndef MDNSPP_SERVICE_H
#define MDNSPP_SERVICE_H

#include <memory>
#include <string>

namespace mdnspp {

class Service
{
    class Impl;
public:
    Service();
    Service(Service &&) = delete;
    Service(const Service &) = delete;
    ~Service();

    void serve(const std::string &name, const std::string &hostname, uint16_t port);
    void stop();

    bool isServing();

private:
    std::unique_ptr<Service::Impl> m_impl;
};

}

#endif
