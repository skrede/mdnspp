#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_BUILDER_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_BUILDER_H

#include "mdnspp/detail/peer_traits.h"
#include "mdnspp/detail/nic_group_peers.h"
#include "mdnspp/detail/nic_group_slots.h"
#include "mdnspp/detail/sibling_records.h"
#include "mdnspp/detail/nic_group_server_callbacks.h"

#include "mdnspp/policy.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_service_server.h"

#include <array>
#include <tuple>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <type_traits>
#include <unordered_set>

namespace mdnspp::detail {

template <policy_like P, template <typename...> class... Peers>
class nic_group_builder
{
    template <std::size_t I>
    using peer_type_at = std::tuple_element_t<I, std::tuple<Peers<P>...>>;

    template <std::size_t I>
    static constexpr bool is_server_at = std::is_same_v<peer_type_at<I>, basic_service_server<P>>;

public:
    using executor_type = typename P::executor_type;
    using socket_options_type = policy_socket_options_t<P>;
    using instance_tuple = typename nic_group_slots<P, Peers...>::instance_tuple;

    nic_group_builder(executor_type ex, basic_nic_group_options<P> &grp_opts, std::shared_ptr<sibling_records> siblings,
                      std::vector<typename peer_traits<Peers, P>::options_type>... peer_opts)
        : m_factory(ex, grp_opts, std::move(siblings))
        , m_peer_opts(std::move(peer_opts)...)
    {
        prepare_peer_options(std::make_index_sequence<sizeof...(Peers)>{});
    }

    bool build(instance_tuple &instances, const network_interface &nic, const socket_options_type &sock_opts,
               const std::unordered_set<std::string> &watches)
    {
        constexpr auto peers = std::make_index_sequence<sizeof...(Peers)>{};
        if(!create_instances(instances, nic, sock_opts, peers))
            return false;
        start_instances(instances, watches, peers);
        return true;
    }

private:
    nic_peer_factory<P> m_factory;
    std::tuple<std::vector<typename peer_traits<Peers, P>::options_type>...> m_peer_opts;
    // Parallel to m_peer_opts; only the entries whose peer is basic_service_server are populated.
    std::array<std::vector<std::shared_ptr<shared_server_callbacks>>, sizeof...(Peers)> m_server_callbacks;

    template <std::size_t... Is>
    void prepare_peer_options(std::index_sequence<Is...>)
    {
        (prepare_peer_options_at<Is>(), ...);
    }

    template <std::size_t I>
    void prepare_peer_options_at()
    {
        auto &vec = std::get<I>(m_peer_opts);
        if constexpr(is_server_at<I>)
        {
            auto &shared_vec = m_server_callbacks[I];
            shared_vec.reserve(vec.size());
            for(auto &opts : vec)
                shared_vec.push_back(share_server_callbacks(opts.service));
        }
        else
        {
            for(const auto &opts : vec)
                reject_peer_callbacks(opts);
        }
    }

    template <std::size_t... Is>
    bool create_instances(instance_tuple &instances, const network_interface &nic, const socket_options_type &sock_opts,
                          std::index_sequence<Is...>)
    {
        return (create_peer_instances<Is>(std::get<Is>(instances), nic, sock_opts) && ...);
    }

    template <std::size_t I>
    bool create_peer_instances(std::vector<std::unique_ptr<peer_type_at<I>>> &instances,
                               const network_interface &nic, const socket_options_type &sock_opts)
    {
        for(std::size_t element = 0; element < std::get<I>(m_peer_opts).size(); ++element)
        {
            auto inst = make_peer<I>(element, nic, sock_opts);
            if(!inst)
                return false;
            instances.push_back(std::move(inst));
        }
        return true;
    }

    template <std::size_t... Is>
    static void start_instances(instance_tuple &instances, const std::unordered_set<std::string> &watches,
                                std::index_sequence<Is...>)
    {
        (start_peer_instances(std::get<Is>(instances), watches), ...);
    }

    template <typename Peer>
    static void start_peer_instances(std::vector<std::unique_ptr<Peer>> &instances,
                                     const std::unordered_set<std::string> &watches)
    {
        for(auto &inst : instances)
            start_peer(*inst, watches);
    }

    template <std::size_t I>
    std::unique_ptr<peer_type_at<I>> make_peer(std::size_t element, const network_interface &nic,
                                               const socket_options_type &sock_opts)
    {
        const auto &opts = std::get<I>(m_peer_opts)[element];
        if constexpr(is_server_at<I>)
            return m_factory.make(opts, m_server_callbacks[I][element], element, nic, sock_opts);
        else
            return m_factory.make(opts, nic, sock_opts);
    }
};

}

#endif
