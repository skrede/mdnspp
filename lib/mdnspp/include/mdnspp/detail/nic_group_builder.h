#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_BUILDER_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_BUILDER_H

#include "mdnspp/detail/peer_traits.h"
#include "mdnspp/detail/nic_group_peers.h"
#include "mdnspp/detail/nic_group_slots.h"
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

    nic_group_builder(executor_type ex, basic_nic_group_options<P> &grp_opts,
                      std::vector<typename peer_traits<Peers, P>::options_type>... peer_opts)
        : m_factory(ex, grp_opts)
        , m_peer_opts(std::move(peer_opts)...)
    {
        prepare_peer_options(std::make_index_sequence<sizeof...(Peers)>{});
    }

    void build(instance_tuple &instances, const network_interface &nic, const socket_options_type &sock_opts,
               const std::unordered_set<std::string> &watches)
    {
        create_instances(instances, nic, sock_opts, watches, std::make_index_sequence<sizeof...(Peers)>{});
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
    void create_instances(instance_tuple &instances, const network_interface &nic, const socket_options_type &sock_opts,
                          const std::unordered_set<std::string> &watches, std::index_sequence<Is...>)
    {
        (create_peer_instances<Is>(std::get<Is>(instances), nic, sock_opts, watches), ...);
    }

    template <std::size_t I>
    void create_peer_instances(std::vector<std::unique_ptr<peer_type_at<I>>> &instances,
                               const network_interface &nic, const socket_options_type &sock_opts,
                               const std::unordered_set<std::string> &watches)
    {
        const auto &peer_opts_vec = std::get<I>(m_peer_opts);
        for(std::size_t element = 0; element < peer_opts_vec.size(); ++element)
        {
            auto inst = make_peer<I>(element, nic, sock_opts);
            start_peer(*inst, watches);
            instances.push_back(std::move(inst));
        }
    }

    template <std::size_t I>
    std::unique_ptr<peer_type_at<I>> make_peer(std::size_t element, const network_interface &nic,
                                               const socket_options_type &sock_opts)
    {
        const auto &opts = std::get<I>(m_peer_opts)[element];
        if constexpr(is_server_at<I>)
            return m_factory.make(opts, m_server_callbacks[I][element], nic, sock_opts);
        else
            return m_factory.make(opts, nic, sock_opts);
    }
};

}

#endif
