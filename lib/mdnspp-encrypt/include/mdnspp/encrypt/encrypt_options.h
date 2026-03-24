#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_OPTIONS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_OPTIONS_H

#include "mdnspp/encrypt/secure_key.h"

#include <cassert>
#include <cstdint>

namespace mdnspp {

enum class cleartext_detection { magic_byte, attempt_decrypt, reject_all };

struct encrypt_options
{
    secure_key psk;
    uint32_t sender_id{0};
    bool accept_cleartext{false};
    uint16_t replay_window_size{64};
    uint16_t max_senders{256};
    cleartext_detection detection{cleartext_detection::magic_byte};
    void validate() const { assert(sender_id != 0 && "encrypt_options::sender_id must be non-zero"); }
};

}

#endif
