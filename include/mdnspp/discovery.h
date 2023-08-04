#ifndef MDNSPP_DISCOVERY_H
#define MDNSPP_DISCOVERY_H

#include <memory>
#include <string>

namespace mdnspp {

class DiscoveryPrivate;

class Discovery
{
    class Impl;
public:
    Discovery();
    Discovery(Discovery &&) = delete;
    Discovery(const Discovery &) = delete;
    ~Discovery();

    void discover();
    void discover_async();
    void stop();

private:
    std::unique_ptr<Discovery::Impl> m_impl;
};

}

#endif