#include "mdnspp/discovery.h"

#include "mdnspp/impl/discovery_impl.h"

mdnspp::Discovery::Discovery()
{
}

mdnspp::Discovery::~Discovery()
{
}

void mdnspp::Discovery::discover()
{
    if(m_impl)
        stop();
    m_impl = std::make_unique<Discovery::Impl>();
    m_impl->send_dns_sd() == 0;
}

void mdnspp::Discovery::discover_async()
{
}

void mdnspp::Discovery::stop()
{
    m_impl->stop();
    m_impl.reset();
}