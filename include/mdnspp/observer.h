#ifndef MDNSPP_OBSERVER_H
#define MDNSPP_OBSERVER_H

#include <memory>
#include <string>

namespace mdnspp {

class observer
{
    class impl;
public:
    observer();
    observer(observer &&) = delete;
    observer(const observer &) = delete;
    ~observer();

    void observe();

    void close();

private:
    std::unique_ptr<observer::impl> m_impl;
};

}

#endif
