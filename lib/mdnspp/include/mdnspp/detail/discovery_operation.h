#ifndef HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_OPERATION_H
#define HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_OPERATION_H

#include "mdnspp/detail/compat.h"

#include "mdnspp/records.h"
#include "mdnspp/service_type.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/resolved_service.h"

#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

class discovery_operation
{
    enum class op_kind : uint8_t
    {
        none,
        discover,
        browse,
        enumerate,
    };

public:
    using enumerate_handler = move_only_function<void(std::error_code, std::vector<service_type_info>)>;

    discovery_operation()
        : m_op(op_kind::none)
    {
    }

    bool active() const noexcept { return m_op != op_kind::none; }

    void start_discover(discovery_completion_handler on_done)
    {
        m_op = op_kind::discover;
        if(on_done)
            m_on_completion = std::move(on_done);
    }

    void start_browse(browse_completion_handler on_done)
    {
        m_op = op_kind::browse;
        if(on_done)
            m_on_browse_completion = std::move(on_done);
    }

    void start_enumerate(enumerate_handler on_done)
    {
        m_op = op_kind::enumerate;
        if(on_done)
            m_on_enumerate_completion = std::move(on_done);
    }

    std::vector<mdns_record_variant> &results() noexcept { return m_results; }
    const std::vector<mdns_record_variant> &results() const noexcept { return m_results; }
    const std::vector<resolved_service> &services() const noexcept { return m_services; }
    std::vector<service_type_info> &enumerated_types() noexcept { return m_enumerated_types; }

    // Browse aggregates even when no handler is pending, unlike complete_pending.
    void complete_naturally()
    {
        switch(m_op)
        {
        case op_kind::discover:
            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{}, m_results);
            break;
        case op_kind::browse:
            m_services = mdnspp::aggregate(m_results);
            if(auto h = std::exchange(m_on_browse_completion, nullptr); h)
                h(std::error_code{}, m_services);
            break;
        case op_kind::enumerate:
            if(auto h = std::exchange(m_on_enumerate_completion, nullptr); h)
                h(std::error_code{}, m_enumerated_types);
            break;
        case op_kind::none:
            break;
        }
    }

    void complete_pending(std::error_code ec)
    {
        switch(m_op)
        {
        case op_kind::discover:
            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(ec, m_results);
            break;
        case op_kind::browse:
            if(auto h = std::exchange(m_on_browse_completion, nullptr); h)
            {
                m_services = mdnspp::aggregate(m_results);
                h(ec, m_services);
            }
            break;
        case op_kind::enumerate:
            if(auto h = std::exchange(m_on_enumerate_completion, nullptr); h)
                h(ec, m_enumerated_types);
            break;
        case op_kind::none:
            break;
        }
    }

private:
    op_kind m_op;
    discovery_completion_handler m_on_completion;
    enumerate_handler m_on_enumerate_completion;
    browse_completion_handler m_on_browse_completion;
    std::vector<mdns_record_variant> m_results;
    std::vector<resolved_service> m_services;
    std::vector<service_type_info> m_enumerated_types;
};

}

#endif
