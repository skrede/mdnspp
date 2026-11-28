#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_TC_CHAINS_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_TC_CHAINS_H

#include "mdnspp/detail/compat.h"

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"

#include <atomic>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>
#include <unordered_map>

namespace mdnspp::detail {

// The remaining packets of a known-answer list that exceeded the payload limit (RFC 6762 section 7.2).
// Each chain owns its timer, so chains started by different watched types in the same scheduler tick
// cannot cancel each other's continuation packets.
template <policy_like P>
class monitor_tc_chains
{
    using executor_type = typename P::executor_type;
    using timer_type = typename P::timer_type;
    using packet_list = std::vector<std::vector<std::byte>>;

    struct tc_chain
    {
        tc_chain(executor_type ex, packet_list pkts, std::size_t i, std::chrono::milliseconds d)
            : timer(ex)
            , packets(std::move(pkts))
            , idx(i)
            , delay(d)
        {
        }

        timer_type timer;
        packet_list packets;
        std::size_t idx;
        std::chrono::milliseconds delay;
    };

public:
    using send_callback = move_only_function<void(const std::vector<std::byte> &)>;

    monitor_tc_chains(executor_type ex, const std::atomic<bool> &stopped, const mdns_options &opts,
                      send_callback send_cb)
        : m_next_id(0)
        , m_send_cb(std::move(send_cb))
        , m_executor(ex)
        , m_opts(opts)
        , m_stopped(stopped)
        , m_chains()
    {
    }

    void send(packet_list packets)
    {
        send_from(std::move(packets), 0);
    }

    void cancel()
    {
        for(auto &[id, chain] : m_chains)
            chain.timer.cancel();
        m_chains.clear();
    }

    std::size_t size() const noexcept { return m_chains.size(); }

    // Only instantiable with timers that expose fire() (mock_policy).
    void fire_for_test()
    {
        std::vector<uint64_t> ids;
        ids.reserve(m_chains.size());
        for(auto &[id, chain] : m_chains)
            ids.push_back(id);
        for(uint64_t id : ids)
        {
            if(auto it = m_chains.find(id); it != m_chains.end())
                it->second.timer.fire();
        }
    }

private:
    uint64_t m_next_id;
    send_callback m_send_cb;
    executor_type m_executor;
    const mdns_options &m_opts;
    const std::atomic<bool> &m_stopped;
    std::unordered_map<uint64_t, tc_chain> m_chains;

    void send_from(packet_list packets, std::size_t idx)
    {
        if(idx >= packets.size() || m_stopped.load(std::memory_order_acquire))
            return;

        m_send_cb(packets[idx]);

        if(idx + 1 >= packets.size())
            return;

        auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(m_opts.tc_continuation_delay);
        if(delay.count() <= 0)
        {
            send_from(std::move(packets), idx + 1);
            return;
        }

        uint64_t id = m_next_id++;
        m_chains.try_emplace(id, m_executor, std::move(packets), idx + 1, delay);
        arm(id);
    }

    void arm(uint64_t id)
    {
        auto &chain = m_chains.find(id)->second;
        chain.timer.expires_after(chain.delay);
        chain.timer.async_wait([this, id](std::error_code ec)
        {
            // ec is checked first and alone: on cancellation (stop teardown or destruction) the chain
            // entry may already be gone.
            if(ec)
                return;
            if(m_stopped.load(std::memory_order_acquire))
                return;
            advance(id);
        });
    }

    void advance(uint64_t id)
    {
        auto it = m_chains.find(id);
        if(it == m_chains.end())
            return;
        auto &chain = it->second;
        m_send_cb(chain.packets[chain.idx]);
        if(++chain.idx < chain.packets.size())
            arm(id);
        else
            m_chains.erase(it);
    }
};

}

#endif
