#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_OPTIONS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_OPTIONS_H

#include "mdnspp/encrypt/secure_key.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <system_error>

namespace mdnspp::encrypt {

enum class cleartext_detection { magic_byte, attempt_decrypt, reject_all };

enum class receive_mode { accept_both, encrypted_only, auth_only };

struct grace_period
{
    std::optional<std::chrono::nanoseconds> duration;
    std::optional<uint64_t>                 packet_count;
};

struct encrypt_options
{
    secure_key psk;
    uint32_t sender_id{0};
    uint32_t initial_epoch{0};
    bool accept_cleartext{false};
    bool auth_only{false};
    uint16_t replay_window_size{64};
    uint16_t max_senders{256};
    cleartext_detection detection{cleartext_detection::magic_byte};
    receive_mode recv_mode{receive_mode::accept_both};
    uint16_t max_sessions_per_sender{8};

    std::error_code validate() const noexcept
    {
        const bool zero_limit = replay_window_size == 0 || max_senders == 0 || max_sessions_per_sender == 0;
        if(sender_id == 0 || zero_limit || psk.is_zero())
            return std::make_error_code(std::errc::invalid_argument);
        return {};
    }
};

}

#endif
