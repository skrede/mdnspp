#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_RECEIVE_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_RECEIVE_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/encrypt_options.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::encrypt {

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
    std::vector<std::byte> plaintext;
};

inline receive_rules rules_of(const encrypt_options &opts) noexcept
{
    return receive_rules{opts.accept_cleartext, opts.detection, opts.recv_mode};
}

inline encrypted_packet_header header_template(const encrypt_options &opts) noexcept
{
    encrypted_packet_header hdr;
    hdr.sender_id = opts.sender_id;
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

inline pre_auth classify_pre_auth(std::span<const std::byte> raw, cleartext_detection detection,
                                  bool accept_cleartext) noexcept
{
    const bool magic = has_magic_prefix(raw);
    if(detection == cleartext_detection::reject_all && !magic)
        return pre_auth::drop;
    if(detection == cleartext_detection::magic_byte && !magic)
        return accept_cleartext ? pre_auth::deliver_cleartext : pre_auth::drop;
    if(raw.size() < encrypted_header_size)
    {
        const bool small_cleartext = detection == cleartext_detection::attempt_decrypt && accept_cleartext && !magic;
        return small_cleartext ? pre_auth::deliver_cleartext : pre_auth::drop;
    }
    return pre_auth::authenticate;
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
                                  std::span<const std::byte> raw)
{
    const auto hdr = deserialize_header(raw.data());
    if(!mode_accepts(rules.mode, hdr.flags))
        return {receive_outcome::drop, {}};

    const auto key = keys.key_for_epoch(hdr.epoch);
    if(!key)
        return {receive_outcome::drop, {}};

    auto result = aead_decrypt(key->key.span(), raw);
    if(!result.has_value())
    {
        const bool as_cleartext = rules.detection == cleartext_detection::attempt_decrypt
            && rules.accept_cleartext && !has_magic_prefix(raw);
        return {as_cleartext ? receive_outcome::deliver_cleartext : receive_outcome::drop, {}};
    }

    if(replay.check_and_record(hdr.sender_id, hdr.sequence).has_value())
        return {receive_outcome::drop, {}};
    if(key->is_previous)
        keys.note_previous_key_packet();
    return {receive_outcome::deliver_plain, std::move(*result)};
}

inline opened_packet open_packet(key_ring &keys, replay_window &replay, const receive_rules &rules,
                                 std::span<const std::byte> raw)
{
    switch(classify_pre_auth(raw, rules.detection, rules.accept_cleartext))
    {
    case pre_auth::deliver_cleartext:
        return {receive_outcome::deliver_cleartext, {}};
    case pre_auth::authenticate:
        return authenticate(keys, replay, rules, raw);
    case pre_auth::drop:
        break;
    }
    return {receive_outcome::drop, {}};
}

}

#endif
