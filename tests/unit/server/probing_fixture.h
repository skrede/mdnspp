#ifndef HPP_GUARD_MDNSPP_SERVER_PROBING_FIXTURE_H
#define HPP_GUARD_MDNSPP_SERVER_PROBING_FIXTURE_H

#include "fixture.h"

#include <string>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

struct conflict_log
{
    conflict_log()
        : called{false}
        , attempt{99}
        , type{conflict_type::name_conflict}
    {
    }

    bool called;
    uint32_t attempt;
    conflict_type type;
};

inline service_options on_conflict_into(conflict_log &log, std::optional<std::string> rename)
{
    service_options opts;
    opts.on_conflict = [&log, rename = std::move(rename)](std::string_view, uint32_t attempt, conflict_type type)
        -> std::optional<std::string>
    {
        log.called = true;
        log.attempt = attempt;
        log.type = type;
        return rename;
    };
    return opts;
}

#endif
