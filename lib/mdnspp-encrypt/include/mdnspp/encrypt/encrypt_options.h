#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_OPTIONS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_OPTIONS_H

#include "mdnspp/encrypt/secure_key.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <algorithm>
#include <system_error>

namespace mdnspp::encrypt {

enum class cleartext_detection { magic_byte, attempt_decrypt, reject_all };

enum class receive_mode { accept_both, encrypted_only, auth_only };

// Dual-key overlap window for update_key(). When neither field is set,
// update_key() applies encrypted_socket::default_grace_duration so that the
// previous key cannot remain accepted indefinitely.
struct grace_period
{
    std::optional<std::chrono::nanoseconds> duration;
    std::optional<uint64_t>                 packet_count;
};

struct encrypt_options
{
    secure_key psk;
    uint32_t sender_id{0};
    // Epoch the socket starts at. A peer that restarts after the group has
    // rotated keys must be provisioned with the current group key and the
    // matching epoch to rejoin (see docs/encrypt/key-rotation.md).
    uint32_t initial_epoch{0};
    bool accept_cleartext{false};
    bool auth_only{false};
    uint16_t replay_window_size{64};
    uint16_t max_senders{256};
    cleartext_detection detection{cleartext_detection::magic_byte};
    receive_mode recv_mode{receive_mode::accept_both};

    // Returns std::errc::invalid_argument if sender_id is zero, the PSK is
    // all-zero, or replay_window_size is zero; a default-constructed
    // std::error_code otherwise. Enforced (in all build configurations) by the
    // encrypted_socket constructors that take encrypt_socket_options.
    [[nodiscard]] std::error_code validate() const noexcept
    {
        const bool zero_key = std::ranges::all_of(psk.bytes(),
            [](std::byte b) { return b == std::byte{0}; });
        if(sender_id == 0 || replay_window_size == 0 || zero_key)
            return std::make_error_code(std::errc::invalid_argument);
        return {};
    }
};

}

#endif
