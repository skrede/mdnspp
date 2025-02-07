#ifndef MDNSPP_LOG_H
#define MDNSPP_LOG_H

#include "mdnspp/logger.h"

#include <memory>
#include <sstream>

namespace mdnspp {

template<log_level L>
class logger
{
public:
    logger(std::shared_ptr<log_sink> sink)
        : m_sink(std::move(sink))
    {
    }

    logger(const std::string &label, std::shared_ptr<log_sink> sink)
        : m_sink(std::move(sink))
    {
        m_stream << std::format("[{}] ", label);
    }

    ~logger()
    {
        if(m_sink)
            m_sink->log(L, m_stream.str());
    }

    template<typename T>
    std::ostream &operator<<(T v)
    {
        if(m_sink)
            m_stream << v;
        return m_stream;
    }

private:
    std::ostringstream m_stream;
    std::shared_ptr<log_sink> m_sink;
};

}

#endif
