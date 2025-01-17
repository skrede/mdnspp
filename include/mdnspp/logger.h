#ifndef MDNSPP_LOGGER_H
#define MDNSPP_LOGGER_H

#include <string>
#include <iostream>

#include <format>

namespace mdnspp {

enum class log_level
{
    trace,
    debug,
    info,
    warn,
    err
};

inline std::string log_level_string(log_level level)
{
    switch(level)
    {
        case log_level::trace:
            return "trace";
        case log_level::debug:
            return "debug";
        case log_level::warn:
            return "warn";
        case log_level::err:
            return "error";
        default:
            return "info";
    }
}

class log_sink
{
public:
    virtual ~log_sink() = default;

    virtual void log(log_level, const std::string &) noexcept
    {
    };
};

template<void (*callable_f)(const std::string &)>
class log_sink_f : public log_sink
{
public:
    void log(log_level level, const std::string &string) noexcept override
    {
        callable_f(std::format("[{}] {}", log_level_string(level), string));
    }

};

template<std::ostream &stream>
class log_sink_s : public log_sink
{
public:
    void log(log_level level, const std::string &string) noexcept override
    {
        stream << "[" << log_level_string(level) << "] " << string << std::endl;
    }

};

}

#endif
