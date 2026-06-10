#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_ERROR_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_ERROR_H

#include <string>
#include <cstdint>
#include <system_error>

namespace mdnspp::encrypt {

enum class encrypt_error : uint32_t
{
    decrypt_failed      = 1,
    replay_detected     = 2,
    unknown_sender      = 3,
    invalid_header      = 4,
    unsupported_version = 5,
    sender_evicted      = 6,
};

const std::error_category &encrypt_error_category() noexcept;
std::error_code make_error_code(encrypt_error e);

}

template <>
struct std::is_error_code_enum<mdnspp::encrypt::encrypt_error> : std::true_type
{
};

#endif
