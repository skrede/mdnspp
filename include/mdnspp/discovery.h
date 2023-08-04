#ifndef MDNSPP_DISCOVERY_H
#define MDNSPP_DISCOVERY_H

#include <memory>
#include <string>

namespace mdnspp {

class discovery
{
    class impl;
public:
    discovery();
    discovery(discovery &&) = delete;
    discovery(const discovery &) = delete;
    ~discovery();

    void discover();
    void discover_async();
    void stop();

private:
    std::unique_ptr<discovery::impl> m_impl;
};

}

#endif
