#ifndef MDNSPP_EXCEPTION_H
#define MDNSPP_EXCEPTION_H

#include <string>
#include <exception>

#ifdef _WIN32
#elifdef __APPLE__
#else
#define SAFE_DYN _GLIBCXX_TXN_SAFE_DYN
#define NOTRHOW _GLIBCXX_NOTHROW
#endif

namespace mdnspp {

class Exception : public std::exception
{
public:
    Exception(const std::string &message) SAFE_DYN NOTRHOW
        : m_message(message)
    {
    }

    Exception(const std::string &message)
        : m_message(message)
    {
    }

    const char *what() const SAFE_DYN NOTRHOW override
    {
        return m_message.c_str();
    }

    const std::string &message() const SAFE_DYN NOTRHOW
    {
        return m_message;
    }

private:
    std::string m_message;
};

}

#endif
