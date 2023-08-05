#include "mdnspp/discovery.h"

#include "mdnspp/impl/discovery_impl.h"

mdnspp::discovery::discovery()
    : m_impl(std::make_unique<discovery::impl>())
{
}

mdnspp::discovery::~discovery()
{
}

void mdnspp::discovery::discover()
{
    m_impl->discover();
}

void mdnspp::discovery::stop()
{
    m_impl->stop();
}