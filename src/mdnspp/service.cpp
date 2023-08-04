#include "mdnspp/service.h"

#include "mdnspp/impl/service_impl.h"

using namespace mdnspp;

Service::Service()
{
}

Service::~Service()
{
}

void Service::serve(const std::string &name, const std::string &hostname, uint16_t port)
{
    m_impl = std::make_unique<Service::Impl>();
    m_impl->serve(hostname.c_str(), name.c_str(), port);
}

void Service::stop()
{
    if(m_impl)
    {
        m_impl->stop();
    }
}

bool Service::isServing()
{
    return m_impl->isServing();
}