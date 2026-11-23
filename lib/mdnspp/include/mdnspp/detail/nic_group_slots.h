#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_SLOTS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_SLOTS_H

#include "mdnspp/detail/nic_family_union.h"
#include "mdnspp/detail/nic_group_family.h"

#include "mdnspp/policy.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_monitor.h"

#include <array>
#include <tuple>
#include <memory>
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
        // Declared before families: the monitors' callbacks reference the unions, which must be destroyed last.
        nic_family_unions unions;
        std::array<instance_tuple, address_families.size()> families;
    };

public:
    bool contains(uint32_t index) const
    {
        return m_slots.contains(index);
    }

    void add(const network_interface &nic, address_family family, instance_tuple instances)
    {
        auto &slot = m_slots[nic.index];
        slot.nic = nic;
        slot.families[family_slot(family)] = std::move(instances);
    }

    void adopt(uint32_t index, nic_family_unions unions)
    {
        if(auto it = m_slots.find(index); it != m_slots.end())
            it->second.unions = std::move(unions);
    }

    void remove(uint32_t index)
    {
        auto it = m_slots.find(index);
        if(it == m_slots.end())
            return;

        stop_families(it->second);
        m_slots.erase(it);
    }

    void stop_all()
    {
        for(auto &[idx, slot] : m_slots)
            stop_families(slot);
    }

    void clear()
    {
        m_slots.clear();
    }

    template <typename Fn>
    void for_each_monitor(Fn &&fn)
    {
        visit_slots(m_slots, [&fn](const network_interface &, auto &inst)
        {
            fn(inst);
        });
    }

    template <typename Fn>
    void visit_monitors(Fn &&fn) const
    {
        visit_slots(m_slots, fn);
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
    static void visit_slots(Slots &slots, Fn &&fn)
    {
        constexpr std::size_t idx = peer_index_of<basic_service_monitor>();
        if constexpr(idx != std::size_t(-1))
        {
            for(auto &[nic_idx, slot] : slots)
            {
                for(auto &instances : slot.families)
                {
                    for(auto &inst_ptr : std::get<idx>(instances))
                        fn(slot.nic, *inst_ptr);
                }
            }
        }
    }

    static void stop_families(nic_slot &slot)
    {
        for(auto &instances : slot.families)
            stop_instance_tuple(instances, std::make_index_sequence<sizeof...(Peers)>{});
    }

    template <std::size_t... Is>
    static void stop_instance_tuple(instance_tuple &instances, std::index_sequence<Is...>)
    {
        (stop_peer_instances(std::get<Is>(instances)), ...);
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
