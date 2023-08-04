#include "mdnspp/discovery.h"

#include "mdnspp/impl/discovery_impl.h"

mdnspp::discovery::discovery()
{
}

mdnspp::discovery::~discovery()
{
}

void mdnspp::discovery::discover()
{
    if(m_impl)
        stop();
    m_impl = std::make_unique<discovery::impl>();
    m_impl->discover() == 0;
}

void mdnspp::discovery::discover_async()
{
}

void mdnspp::discovery::stop()
{
    m_impl->stop();
    m_impl.reset();
}