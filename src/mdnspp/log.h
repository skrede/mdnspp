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

inline void except(const std::string &msg)
{
    throw Exception(msg);
}

inline void cout(const std::string &msg)
{
    std::cout << msg << std::endl;
}

inline ErrorStream<mdnspp::except> error()
{
    return {};
}

inline ErrorStream<mdnspp::cout> info()
{
    return {};
}

}

#endif
