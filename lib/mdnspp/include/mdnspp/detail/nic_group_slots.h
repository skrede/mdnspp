#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_SLOTS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_SLOTS_H

#include "mdnspp/policy.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_monitor.h"

#include <tuple>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <unordered_map>

namespace mdnspp::detail {

template <policy_like P, template <typename...> class... Peers>
class nic_group_slots
{
public:
    using instance_tuple = std::tuple<std::vector<std::unique_ptr<Peers<P>>>...>;

private:
    struct nic_slot
    {
        network_interface nic;
        instance_tuple instances;
    };

public:
    bool contains(uint32_t index) const
    {
        return m_slots.contains(index);
    }

    instance_tuple &add(const network_interface &nic)
    {
        auto &slot = m_slots[nic.index];
        slot.nic = nic;
        return slot.instances;
    }

    void remove(uint32_t index)
    {
        auto it = m_slots.find(index);
        if(it == m_slots.end())
            return;

        stop_instance_tuple(it->second.instances, std::make_index_sequence<sizeof...(Peers)>{});
        m_slots.erase(it);
    }

    void stop_all()
    {
        for(auto &[idx, slot] : m_slots)
            stop_instance_tuple(slot.instances, std::make_index_sequence<sizeof...(Peers)>{});
    }

    void clear()
    {
        m_slots.clear();
    }

    template <typename Fn>
    void for_each_monitor(Fn &&fn)
    {
        visit_monitors(m_slots, [&fn](const network_interface &, auto &inst)
        {
            fn(inst);
        });
    }

    std::vector<resolved_service> collect_merged() const
    {
        std::unordered_map<std::string, resolved_service> by_name;
        visit_monitors(m_slots, [&by_name](const network_interface &nic, const auto &inst)
        {
            for(auto svc : inst.services())
            {
                svc.source_interface = nic;
                // ASCII-folded key: case variants of one instance observed on different interfaces merge to one
                // entry (RFC 6762 section 16).
                auto key = svc.instance_name.comparison_key();
                by_name[key] = std::move(svc);
            }
        });

        std::vector<resolved_service> result;
        result.reserve(by_name.size());
        for(auto &[k, v] : by_name)
            result.push_back(std::move(v));
        return result;
    }

    std::vector<resolved_service> collect_per_interface() const
    {
        std::vector<resolved_service> result;
        visit_monitors(m_slots, [&result](const network_interface &nic, const auto &inst)
        {
            for(auto svc : inst.services())
            {
                svc.source_interface = nic;
                result.push_back(std::move(svc));
            }
        });
        return result;
    }

private:
    std::unordered_map<uint32_t, nic_slot> m_slots;

    template <template <typename...> class PeerTemplate,
              template <typename...> class Head,
              template <typename...> class... Tail>
    static constexpr std::size_t peer_index_of_impl(std::size_t current)
    {
        if constexpr(std::is_same_v<PeerTemplate<P>, Head<P>>)
            return current;
        else if constexpr(sizeof...(Tail) == 0)
            return std::size_t(-1);
        else
            return peer_index_of_impl<PeerTemplate, Tail...>(current + 1);
    }

    template <template <typename...> class PeerTemplate>
    static constexpr std::size_t peer_index_of()
    {
        return peer_index_of_impl<PeerTemplate, Peers...>(0);
    }

    template <typename Slots, typename Fn>
    static void visit_monitors(Slots &slots, Fn &&fn)
    {
        constexpr std::size_t idx = peer_index_of<basic_service_monitor>();
        if constexpr(idx != std::size_t(-1))
        {
            for(auto &[nic_idx, slot] : slots)
            {
                for(auto &inst_ptr : std::get<idx>(slot.instances))
                {
                    if(inst_ptr)
                        fn(slot.nic, *inst_ptr);
                }
            }
        }
    }

    template <std::size_t... Is>
    static void stop_instance_tuple(instance_tuple &slot, std::index_sequence<Is...>)
    {
        (stop_peer_instances(std::get<Is>(slot)), ...);
    }

    template <typename PeerType>
    static void stop_peer_instances(std::vector<std::unique_ptr<PeerType>> &vec)
    {
        for(auto &inst : vec)
        {
            if(inst)
                inst->stop();
        }
        vec.clear();
    }
};

}

#endif
