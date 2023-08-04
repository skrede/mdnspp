#include "mdnspp/discovery.h"

#include "mdnspp/impl/discoveryprivate.h"

mdnspp::Discovery::Discovery()
{
}

mdnspp::Discovery::~Discovery()
{
}

void mdnspp::Discovery::discover()
{
    if(m_discovery)
        stop();
    m_discovery = std::make_unique<DiscoveryPrivate>();
    m_discovery->send_dns_sd() == 0;
}

void mdnspp::Discovery::discover_async()
{
}

void mdnspp::Discovery::stop()
{
    m_discovery->stop();
    m_discovery.reset();
}