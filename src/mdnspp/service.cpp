#include "mdnspp/service.h"

#include "mdnspp/impl/service_impl.h"

using namespace mdnspp;

service::service()
{
}

service::~service()
{
}

void service::serve(const std::string &name, const std::string &hostname, uint16_t port)
{
    m_impl = std::make_unique<service::impl>(hostname.c_str(), name.c_str(), port);
    m_impl->serve();
}

void service::stop()
{
    if(m_impl)
    {
        m_impl->stop();
    }
}

bool service::isServing()
{
    return m_impl->isServing();
}