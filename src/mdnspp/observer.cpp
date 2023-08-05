#include "mdnspp/observer.h"

#include "mdnspp/impl/observer_impl.h"

using namespace mdnspp;

observer::observer()
    : m_impl(std::make_unique<observer::impl>())
{
}

observer::~observer()
{
}

void observer::observe()
{
    m_impl->observe();
}

void observer::close()
{
    m_impl->stop();
}