#ifndef MDNSPP_THROW_H
#define MDNSPP_THROW_H

#include "mdnspp/exception.h"

#include <sstream>
#include <iostream>

namespace mdnspp {

template<void (*callable_t)(const std::string &)>
class error_stream
{
public:
    error_stream() = default;
    error_stream(const std::string &label)
    {
        m_stream << "[" << label << "] ";
    }

    ~error_stream()
    {
        callable_t(m_stream.str());
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
    throw Exception(msg);
}

inline void cout(const std::string &msg)
{
    std::cout << msg << std::endl;
}

inline void cerr(const std::string &msg)
{
    std::cerr << msg << std::endl;
}

inline error_stream<mdnspp::throw_except> exception()
{
    return {};
}

inline error_stream<mdnspp::cout> debug()
{
    return {};
}

inline error_stream<mdnspp::cout> info()
{
    return {};
}

inline error_stream<mdnspp::cerr> error()
{
    return {};
}

}

#endif
