#ifndef HPP_GUARD_MDNSPP_INPROC_BUS_TTL_HELPERS_H
#define HPP_GUARD_MDNSPP_INPROC_BUS_TTL_HELPERS_H

#include "inproc_bus/helpers.h"

#include "mdnspp/inproc/detail/inproc_receive_queue.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"

#include "mdnspp/detail/dns_response.h"

#include <map>
#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <optional>
#include <string_view>

inline std::vector<std::byte> make_ptr_response(std::string_view service_name, std::string_view service_type,
                                                std::string_view host, uint16_t port)
{
    service_options srv_opts;
    return detail::build_dns_response(make_service(service_name, service_type, host, port), dns_type::ptr, srv_opts);
}

// The PTR answer and its SRV, A and TXT additionals.
inline constexpr std::size_t ptr_response_records = 4;

inline mdns_options ttl_floor(uint32_t minimum)
{
    mdns_options opts;
    opts.receive_ttl_minimum = minimum;
    return opts;
}

inline mdns_options ttl_floor(uint32_t minimum, ttl_unknown_policy policy)
{
    mdns_options opts = ttl_floor(minimum);
    opts.unknown_ttl_policy = policy;
    return opts;
}

struct counting_observer
{
    counting_observer(inproc_harness &h, mdns_options mdns_opts)
        : records{0}, harness{h}, observer{h.make_observer(record_counter(records), {}, std::move(mdns_opts))}
    {
        observer.async_observe();
        h.executor.drain();
    }

    void deliver(const endpoint &from, std::span<const std::byte> packet, std::optional<uint8_t> ttl)
    {
        recv_metadata meta = detail::inproc_metadata(from, observer.socket().options().multicast_group);
        meta.ttl = ttl;
        observer.socket().deliver(meta, packet);
        harness.executor.drain();
    }

    std::size_t records;
    inproc_harness &harness;
    inproc_observer observer;
};

inline service_options distinct_ttl_opts()
{
    service_options opts;
    opts.ptr_ttl = std::chrono::seconds{100};
    opts.srv_ttl = std::chrono::seconds{200};
    opts.txt_ttl = std::chrono::seconds{300};
    opts.a_ttl = std::chrono::seconds{400};
    opts.aaaa_ttl = std::chrono::seconds{500};
    opts.fallback_record_ttl = std::chrono::seconds{600};
    opts.respond_to_meta_queries = false;
    return opts;
}

struct ttl_collector
{
    ttl_collector(std::string_view instance_label, std::string_view host_label, bool capturing)
        : capture{capturing}, host{host_label}, instance{instance_label}, ttl_by_type{}
    {
    }

    observer_options options()
    {
        observer_options opts;
        opts.on_record = [this](const endpoint &, const mdns_record_variant &rec)
        {
            if(capture)
                std::visit([this](const auto &r) { collect(r); }, rec);
        };
        return opts;
    }

    void collect(const record_ptr &r) { keep("ptr", r, "_http._tcp"); }
    void collect(const record_srv &r) { keep("srv", r, instance); }
    void collect(const record_txt &r) { keep("txt", r, instance); }
    void collect(const record_a &r) { keep("a", r, host); }
    void collect(const record_aaaa &r) { keep("aaaa", r, host); }

    template <typename T>
    void collect(const T &)
    {
    }

    template <typename T>
    void keep(const std::string &type, const T &r, std::string_view owner)
    {
        if(r.name.find(owner) != dns_name::npos)
            ttl_by_type[type] = r.ttl;
    }

    bool capture;
    std::string host;
    std::string instance;
    std::map<std::string, uint32_t> ttl_by_type;
};

#endif
