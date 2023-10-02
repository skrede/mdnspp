#ifndef MDNSPP_LOG_H
#define MDNSPP_LOG_H

#include "mdnspp/logger.h"

#include <memory>
#include <sstream>
#include <functional>

namespace mdnspp {

template<log_level L>
class logger
{
public:
    logger(const std::string &label, std::shared_ptr<log_sink> sink) noexcept
        : m_sink(std::move(sink))
    {
        m_stream << fmt::format("[{}]", label);
    }

    logger(std::shared_ptr<log_sink> sink) noexcept
        : m_sink(std::move(sink))
    {
    }

    ~logger() noexcept
    {
        if(m_sink)
            m_sink->log(L, m_stream.str());
    }

    template<typename T>
    std::ostream &operator<<(T v) noexcept
    {
        m_stream << v;
        return m_stream;
    }

private:
    std::ostringstream m_stream;
    std::shared_ptr<log_sink> m_sink;
};

}

#endif
