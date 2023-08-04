#ifndef MDNSPP_THROW_H
#define MDNSPP_THROW_H

#include "mdnspp/exception.h"

#include <sstream>

namespace mdnspp {

template<void (*Callable_t)(const std::string &)>
class ErrorStream
{
public:
    ~ErrorStream()
    {
        Callable_t(m_stream.str());
    }

    template<typename T>
    std::ostream &operator<<(T v)
    {
        m_stream << v;
        return m_stream;
    }

private:
    std::stringstream m_stream;
};

inline void except(const std::string &msg)
{
    throw Exception(msg);
}

inline ErrorStream<mdnspp::except> error()
{
    return {};
}

}

#endif
