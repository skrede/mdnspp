#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_RECEIVER_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_RECEIVER_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypted_receive.h"

#include <span>
#include <vector>
#include <cstddef>
#include <utility>
#include <system_error>

namespace mdnspp::encrypt {

template <socket_like InnerSocket>
class encrypted_receiver
{
    using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

public:
    encrypted_receiver(InnerSocket &inner, key_ring &keys, const encrypt_options &opts)
        : m_inner(inner)
        , m_keys(keys)
        , m_receive_cb()
        , m_replay(opts.replay_window_size, opts.max_senders, opts.max_sessions_per_sender)
        , m_rules(rules_of(opts))
        , m_recv_buf(detail::max_udp_payload)
        , m_closed(false)
        , m_arming(false)
        , m_rearm_requested(false)
    {
    }

    encrypted_receiver(const encrypted_receiver &) = delete;
    encrypted_receiver &operator=(const encrypted_receiver &) = delete;

    void arm(receive_handler handler)
    {
        if(m_closed || !m_keys.has_key())
            return;
        m_receive_cb = std::move(handler);
        arm_inner();
    }

    void close()
    {
        m_closed = true;
        m_receive_cb = nullptr;
    }

private:
    InnerSocket &m_inner;
    key_ring &m_keys;
    receive_handler m_receive_cb;
    replay_window m_replay;
    receive_rules m_rules;
    std::vector<std::byte> m_recv_buf;
    bool m_closed;
    bool m_arming;
    bool m_rearm_requested;

    // Iterative so an inner socket that completes inline cannot grow the
    // stack however many consecutive packets are rejected.
    void arm_inner()
    {
        m_rearm_requested = true;
        if(m_arming)
            return;
        scoped_flag arming(m_arming);
        while(m_rearm_requested && !m_closed)
        {
            m_rearm_requested = false;
            m_inner.async_receive([this](std::error_code ec, const recv_metadata &meta, std::span<std::byte> raw)
            {
                on_inner(ec, meta, raw);
            });
        }
    }

    void on_inner(std::error_code ec, const recv_metadata &meta, std::span<std::byte> raw)
    {
        if(m_closed)
            return;
        if(ec)
            return complete(ec, meta, raw);

        const auto opened = open_packet(m_keys, m_replay, m_rules, raw, m_recv_buf);
        if(opened.outcome == receive_outcome::drop)
            return arm_inner();
        const bool plain = opened.outcome == receive_outcome::deliver_plain;
        complete(std::error_code{}, meta, plain ? std::span<std::byte>(m_recv_buf.data(), opened.written) : raw);
    }

    void complete(std::error_code ec, const recv_metadata &meta, std::span<std::byte> data)
    {
        auto handler = std::exchange(m_receive_cb, nullptr);
        if(handler)
            handler(ec, meta, data);
    }
};

}

#endif
