#include "mdnspp/service.h"

#include "mdnspp/impl/serviceprivate.h"

using namespace mdnspp;

Service::Service()
{
}

Service::~Service()
{
}

void Service::serve(const std::string &name, const std::string &hostname, uint16_t port)
{
    m_service = std::make_unique<ServicePrivate>();
    m_service->serve(hostname.c_str(), name.c_str(), port);
}

void Service::stop()
{
    if(m_service)
    {
        m_service->stop();
    }
}

bool Service::isServing()
{
    return m_service->isServing();
}