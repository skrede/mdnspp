#include <mdnspp/encrypt/aead.h>
#include <mdnspp/encrypt/defaults.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <variant>
#include <iostream>
#include <optional>
#include <string_view>

// Observe encrypted mDNS multicast traffic using default_policy.
//
// Encrypted mDNS is not defined by any RFC. It is a project-specific extension
// that wraps standard mDNS multicast traffic with XChaCha20-Poly1305 AEAD.
//
// What the encryption protects:
//   - Confidentiality: the DNS payload (service names, hostnames, IP addresses,
//     TXT records) is encrypted and invisible to observers without the PSK.
//   - Integrity: the Poly1305 authentication tag prevents injection or tampering;
//     any packet that does not authenticate is silently dropped.
//
// PSK distribution is the application's responsibility:
//   The library provides no key negotiation protocol. All peers must obtain the
//   same 32-byte key through an out-of-band mechanism (e.g., configuration file,
//   environment variable, secure channel).
//
// sender_id:
//   Must be non-zero and unique per sender within the multicast group. It appears
//   in the wire header in plaintext and is used for per-sender anti-replay
//   tracking (each sender has an independent sequence counter).
//
// Transparent decryption:
//   encrypted_observer decrypts each received packet before invoking on_record.
//   The application receives plain mdns_record_variant values; the encryption
//   layer is invisible above the socket.

static std::array<std::byte, 32> example_key()
{
    // Never use a hardcoded key in production: anyone who reads this source code has the key.
    return std::array<std::byte, 32>{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
        std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C},
        std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F}, std::byte{0x10},
        std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18},
        std::byte{0x19}, std::byte{0x1A}, std::byte{0x1B}, std::byte{0x1C},
        std::byte{0x1D}, std::byte{0x1E}, std::byte{0x1F}, std::byte{0x20},
    };
}

static std::optional<uint8_t> hex_value(char c)
{
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return std::nullopt;
}

static std::optional<std::array<std::byte, 32>> parse_hex_key(std::string_view hex)
{
    std::array<std::byte, 32> key{};
    if(hex.size() != 2 * key.size())
        return std::nullopt;
    for(std::size_t i = 0; i < key.size(); ++i)
    {
        const std::optional<uint8_t> high = hex_value(hex[2 * i]);
        const std::optional<uint8_t> low = hex_value(hex[2 * i + 1]);
        if(!high || !low)
            return std::nullopt;
        key[i] = std::byte{static_cast<uint8_t>(*high << 4 | *low)};
    }
    return key;
}

// In production, load a 32-byte key from a file, hardware token, or configuration system. This example reads a
// hex-encoded 64-character PSK from the MDNSPP_PSK environment variable and falls back to a fixed example key.
static std::optional<std::array<std::byte, 32>> load_psk_from_env()
{
    const char *env = std::getenv("MDNSPP_PSK");
    if (!env)
        return example_key();
    return parse_hex_key(env);
}

static mdnspp::encrypt::encrypt_socket_options make_socket_options(std::array<std::byte, 32> &raw_key)
{
    // secure_key copies the std::array<std::byte, 32> and zeroes its own copy
    // in the destructor. The caller's source buffer is the caller's
    // responsibility: wipe it once the secure_key has been constructed,
    // otherwise the key material remains on the stack.
    mdnspp::encrypt::secure_key psk{raw_key};
    mdnspp::encrypt::secure_zero(raw_key.data(), raw_key.size());

    // encrypt_socket_options extends socket_options (interface address, multicast
    // TTL, etc.) with a nested encrypt_options field.
    // sender_id must be non-zero. Real deployments should derive it from a stable
    // device identity (e.g., a truncated hash of the MAC address or a UUID).
    return mdnspp::encrypt::encrypt_socket_options{
        .encrypt = {
            .psk       = std::move(psk),
            .sender_id = 0x00000001,
            // accept_cleartext defaults to false: unencrypted packets are dropped.
            // Set to true during gradual migration if legacy (plain) peers are present.
        },
    };
}

static mdnspp::observer_options make_observer_options()
{
    return mdnspp::observer_options{
        .on_record = [](const mdnspp::endpoint &sender,
                        const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&sender](const auto &r) {
                std::cout << sender << " -> " << r << std::endl;
            }, rec);
        }
    };
}

int main()
{
    std::optional<std::array<std::byte, 32>> raw_key = load_psk_from_env();
    if(!raw_key)
    {
        std::cerr << "MDNSPP_PSK must hold exactly 64 hexadecimal digits (a 32-byte key)" << std::endl;
        return EXIT_FAILURE;
    }

    // encrypted_observer is defined in mdnspp/encrypt/defaults.h as:
    //   using encrypted_observer = basic_observer<encrypted_policy<default_policy>>;
    // Constructor order: (executor, observer_options, encrypt_socket_options).
    mdnspp::context ctx;
    mdnspp::encrypt::encrypted_observer obs{ctx, make_observer_options(), make_socket_options(*raw_key)};

    obs.async_observe([&ctx](std::error_code ec)
    {
        if (ec)
            std::cerr << "observe error: " << ec.message() << std::endl;
        ctx.stop();
    });

    ctx.run();
}
