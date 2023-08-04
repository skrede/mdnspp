#ifndef MDNSPP_OBSERVER_H
#define MDNSPP_OBSERVER_H

#include <memory>
#include <string>

namespace mdnspp {

class ObserverPrivate;

class Observer
{
public:
    Observer();
    Observer(Observer &&) = delete;
    Observer(const Observer &) = delete;
    ~Observer();

    void observe();
    void observe_async();

    void close();

private:
    std::unique_ptr<ObserverPrivate> m_observer;
};

}

#endif
