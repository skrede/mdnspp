#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_MODEL_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_MODEL_H

#include "mdnspp/resolved_service.h"

#include <vector>
#include <utility>
#include <string_view>

namespace mdnspp::detail {

struct nic_group_concept
{
    virtual ~nic_group_concept() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::vector<resolved_service> services() const = 0;
    virtual void watch(std::string_view service_type) = 0;
    virtual void unwatch(std::string_view service_type) = 0;
};

template <typename Concrete>
struct nic_group_model final : nic_group_concept
{
    template <typename... Args>
    explicit nic_group_model(Args &&...args)
        : m_impl(std::forward<Args>(args)...)
    {
    }

    void start() override { m_impl.start(); }
    void stop() override { m_impl.stop(); }

    std::vector<resolved_service> services() const override
    {
        if constexpr(requires { m_impl.services(); })
            return m_impl.services();
        else
            return {};
    }

    void watch(std::string_view service_type) override
    {
        if constexpr(requires { m_impl.watch(service_type); })
            m_impl.watch(service_type);
    }

    void unwatch(std::string_view service_type) override
    {
        if constexpr(requires { m_impl.unwatch(service_type); })
            m_impl.unwatch(service_type);
    }

    Concrete m_impl;
};

}

#endif
