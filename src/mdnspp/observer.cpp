#include "mdnspp/observer.h"

#include "mdnspp/impl/observer_impl.h"

using namespace mdnspp;

Observer::Observer()
{
}

Observer::~Observer()
{
}

void Observer::observe()
{
    if(m_impl)
        close();
    m_impl = std::make_unique<Observer::Impl>();
    m_impl->dump_mdns();
}

void Observer::observe_async()
{
}

void Observer::close()
{
}