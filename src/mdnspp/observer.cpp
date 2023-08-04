#include "mdnspp/observer.h"

#include "mdnspp/impl/observer_impl.h"

using namespace mdnspp;

observer::observer()
{
}

observer::~observer()
{
}

void observer::observe()
{
    if(m_impl)
        close();
    m_impl = std::make_unique<observer::impl>();
    m_impl->observe();
}

void observer::observe_async()
{
}

void observer::close()
{
}