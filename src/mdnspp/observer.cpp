#include "mdnspp/observer.h"

#include "mdnspp/impl/observerprivate.h"

using namespace mdnspp;

Observer::Observer()
{
}

Observer::~Observer()
{
}

void Observer::observe()
{
    if(m_observer)
        close();
    m_observer = std::make_unique<ObserverPrivate>();
    m_observer->dump_mdns();
}

void Observer::observe_async()
{
}

void Observer::close()
{
}