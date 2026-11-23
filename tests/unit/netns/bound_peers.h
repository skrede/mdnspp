#ifndef HPP_GUARD_MDNSPP_NETNS_BOUND_PEERS_H
#define HPP_GUARD_MDNSPP_NETNS_BOUND_PEERS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"

#include "mdnspp/default/default_policy.h"

#include "mdnspp/detail/dns_response.h"
#include "mdnspp/detail/native_sockaddr.h"

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

#include <sys/socket.h>

#include <cerrno>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <algorithm>
#include <string_view>

inline constexpr uint16_t mdns_port = 5353;

inline void run_for(mdnspp::default_context &ctx, std::chrono::milliseconds span)
{
    mdnspp::default_timer deadline{ctx};
    deadline.expires_after(span);
    deadline.async_wait([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
    ctx.restart();
}

inline mdnspp::socket_options bound_to(const std::string &device, const std::string &group)
{
    return mdnspp::socket_options{.interface_name = device, .multicast_group = mdnspp::endpoint{group, mdns_port}};
}

inline mdnspp::service_info attribution_service()
{
    mdnspp::service_info info;
    info.service_name = "Attribution._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "attribution.local.";
    info.port = 8080;
    info.address_ipv4 = "192.0.2.1";
    return info;
}

inline void announce_and_close(int32_t fd, const std::string &group)
{
    const std::vector<std::byte> packet =
        mdnspp::detail::build_dns_response(attribution_service(), mdnspp::dns_type::ptr, mdnspp::service_options{});
    const std::optional<mdnspp::detail::sockaddr_result> to =
        mdnspp::detail::build_sockaddr(mdnspp::endpoint{group, mdns_port});
    REQUIRE(to.has_value());
    const ssize_t sent = ::sendto(fd, packet.data(), packet.size(), 0, reinterpret_cast<const sockaddr *>(&to->ss),
                                  to->len);
    INFO("send to " << group << ": " << std::strerror(errno));
    ::close(fd);
    REQUIRE(sent == static_cast<ssize_t>(packet.size()));
}

struct recording_observer
{
    recording_observer(mdnspp::default_context &ctx, const mdnspp::socket_options &opts)
        : senders{}
        , peer{ctx, mdnspp::observer_options{.on_record = [this](const mdnspp::endpoint &from,
                                                                 const mdnspp::mdns_record_variant &)
          {
              senders.push_back(from.address);
          }}, opts}
    {
        peer.async_observe();
    }

    std::size_t records_from(std::string_view address) const
    {
        return static_cast<std::size_t>(std::ranges::count(senders, address));
    }

    std::vector<std::string> senders;
    mdnspp::basic_observer<mdnspp::default_policy> peer;
};

struct bound_observers
{
    explicit bound_observers(const std::string &group)
        : ctx{}
        , on_d0{ctx, bound_to("d0", group)}
        , on_d1{ctx, bound_to("d1", group)}
    {
    }

    void settle() { run_for(ctx, std::chrono::milliseconds{500}); }

    mdnspp::default_context ctx;
    recording_observer on_d0;
    recording_observer on_d1;
};

#endif
