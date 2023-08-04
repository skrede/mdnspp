#ifndef MDNSPP_THROW_H
#define MDNSPP_THROW_H

#include "mdnspp/exception.h"

#include <sstream>
#include <iostream>

namespace mdnspp {

template<void (*Callable_t)(const std::string &)>
class ErrorStream
{
public:
    ErrorStream() = default;
    ErrorStream(const std::string &label)
    {
        m_stream << "[" << label << "] ";
    }

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
    std::ostringstream m_stream;
};

inline void throw_except(const std::string &msg)
{
    throw exception(msg);
}

inline void cout(const std::string &msg)
{
    std::cout << msg << std::endl;
}

inline ErrorStream<mdnspp::throw_except> exception()
{
    return {};
}

inline ErrorStream<mdnspp::cout> info()
{
    return {};
}

inline ErrorStream<mdnspp::cout> debug()
{
    return {};
}

}

#endif
