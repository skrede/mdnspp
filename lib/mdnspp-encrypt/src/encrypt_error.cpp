#include "mdnspp/encrypt/encrypt_error.h"

namespace mdnspp {

const std::error_category &encrypt_error_category() noexcept
{
    struct category : std::error_category
    {
        const char *name() const noexcept override { return "mdnspp.encrypt"; }

        std::string message(int ev) const override
        {
            switch(static_cast<encrypt_error>(ev))
            {
            case encrypt_error::decrypt_failed: return "decryption or authentication failed";
            case encrypt_error::replay_detected: return "replayed sequence number";
            case encrypt_error::unknown_sender: return "unknown sender ID";
            case encrypt_error::invalid_header: return "invalid packet header";
            case encrypt_error::unsupported_version: return "unsupported protocol version";
            case encrypt_error::sender_evicted: return "sender evicted from replay window";
            }
            return "unknown encrypt error";
        }
    };

    static const category instance;
    return instance;
}

std::error_code make_error_code(encrypt_error e)
{
    return {static_cast<int>(e), encrypt_error_category()};
}

}
