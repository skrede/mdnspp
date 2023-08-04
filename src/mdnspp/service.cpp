#include "mdnspp/service.h"

#include "mdnspp/impl/service_impl.h"

using namespace mdnspp;

service::service(const std::string &name, const std::string &hostname, uint16_t port)
    : m_impl(std::make_unique<service::impl>(hostname.c_str(), name.c_str(), port))
{
}

service::~service()
{
}

void service::serve()
{
    m_impl->serve();
}

void service::stop()
{
    m_impl->stop();
}

bool service::isServing()
{
    return m_impl->is_serving();
}