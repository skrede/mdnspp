#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_RECEIVE_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_RECEIVE_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/encrypt_options.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::encrypt {

// The shortest header any wire version has used. A magic-prefixed packet at least this long is never
// delivered as cleartext, so ciphertext of an older version cannot reach the handler.
inline constexpr std::size_t smallest_known_header_size = 44;

enum class receive_outcome { deliver_plain, deliver_cleartext, drop };

enum class pre_auth { authenticate, deliver_cleartext, drop };

struct receive_rules
{
    bool accept_cleartext;
    cleartext_detection detection;
    receive_mode mode;
};

struct opened_packet
{
    receive_outcome outcome;
    std::size_t written;
};

inline receive_rules rules_of(const encrypt_options &opts) noexcept
{
    return receive_rules{opts.accept_cleartext, opts.detection, opts.recv_mode};
}

inline encrypted_packet_header header_template(const encrypt_options &opts, uint64_t session_id) noexcept
{
    encrypted_packet_header hdr;
    hdr.sender_id = opts.sender_id;
    hdr.session_id = session_id;
    hdr.flags = opts.auth_only ? uint8_t{0} : flag_encrypted;
    return hdr;
}

inline std::error_code skip_validation(const encrypt_options &) noexcept
{
    return {};
}

inline std::error_code validate_or_throw(const encrypt_options &opts)
{
    if(auto ec = opts.validate())
        throw std::system_error(ec, "mdnspp::encrypt: invalid encrypt_options");
    return {};
}

inline bool has_magic_prefix(std::span<const std::byte> raw) noexcept
{
    return raw.size() >= 2 && raw[0] == std::byte{0x4D} && raw[1] == std::byte{0x43};
}

inline pre_auth classify_magic_prefixed(std::span<const std::byte> raw, cleartext_detection detection,
                                        bool accept_cleartext) noexcept
{
    if(raw.size() < smallest_known_header_size)
    {
        const bool fall_through = accept_cleartext && detection == cleartext_detection::attempt_decrypt;
        return fall_through ? pre_auth::deliver_cleartext : pre_auth::drop;
    }
    const bool parses = raw.size() >= encrypted_overhead && raw[2] == std::byte{encrypted_version};
    return parses ? pre_auth::authenticate : pre_auth::drop;
}

inline pre_auth classify_pre_auth(std::span<const std::byte> raw, cleartext_detection detection,
                                  bool accept_cleartext) noexcept
{
    if(has_magic_prefix(raw))
        return classify_magic_prefixed(raw, detection, accept_cleartext);
    const bool deliver = accept_cleartext && detection != cleartext_detection::reject_all;
    return deliver ? pre_auth::deliver_cleartext : pre_auth::drop;
}

inline bool mode_accepts(receive_mode mode, uint8_t flags) noexcept
{
    const bool is_encrypted = (flags & flag_encrypted) != 0;
    if(mode == receive_mode::encrypted_only)
        return is_encrypted;
    if(mode == receive_mode::auth_only)
        return !is_encrypted;
    return true;
}

inline opened_packet authenticate(key_ring &keys, replay_window &replay, const receive_rules &rules,
                                  std::span<const std::byte> raw, std::span<std::byte> out)
{
    const auto hdr = deserialize_header(raw.data());
    const auto key = keys.key_for_epoch(hdr.epoch);
    if(!key)
        return {receive_outcome::drop, 0};

    std::size_t written = 0;
    if(aead_decrypt(key->key.span(), raw, out, written) || !mode_accepts(rules.mode, hdr.flags))
        return {receive_outcome::drop, 0};
    if(replay.check_and_record(hdr.sender_id, hdr.session_id, hdr.sequence).has_value())
        return {receive_outcome::drop, 0};
    if(key->is_previous)
        keys.note_previous_key_packet();
    return {receive_outcome::deliver_plain, written};
}

inline opened_packet open_packet(key_ring &keys, replay_window &replay, const receive_rules &rules,
                                 std::span<const std::byte> raw, std::span<std::byte> out)
{
    switch(classify_pre_auth(raw, rules.detection, rules.accept_cleartext))
    {
    case pre_auth::deliver_cleartext:
        return {receive_outcome::deliver_cleartext, 0};
    case pre_auth::authenticate:
        return authenticate(keys, replay, rules, raw, out);
    case pre_auth::drop:
        break;
    }
    return {receive_outcome::drop, 0};
}

}

#endif
