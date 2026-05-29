#include "mdnspp/encrypt/defaults.h"

#include <array>
#include <cstddef>
#include <cstdlib>
#include <utility>
#include <iostream>
#include <variant>

// Observe encrypted mDNS multicast traffic using DefaultPolicy.
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

static std::array<std::byte, 32> load_psk_from_env()
{
    // In production, load a 32-byte key from a file, hardware token, or
    // configuration system. This example reads a hex-encoded 64-character PSK
    // from the MDNSPP_PSK environment variable for demonstration purposes.
    const char *env = std::getenv("MDNSPP_PSK");
    if (!env)
    {
        // Fall back to a fixed example key. Never use a hardcoded key in
        // production: anyone who reads this source code has the key.
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

    std::array<std::byte, 32> key{};
    for (std::size_t i = 0; i < 32 && env[i * 2] != '\0' && env[i * 2 + 1] != '\0'; ++i)
    {
        auto hex_char = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        key[i] = std::byte{static_cast<uint8_t>(hex_char(env[i * 2]) << 4 | hex_char(env[i * 2 + 1]))};
    }
    return key;
}

int main()
{
    // Step 1: Load the PSK from an application-managed source.
    // secure_key accepts a std::array<std::byte, 32> and zeroes its own storage
    // in the destructor, preventing key material from lingering in memory.
    std::array<std::byte, 32> raw_key = load_psk_from_env();
    mdnspp::secure_key psk{raw_key};

    // Step 2: Populate encrypt_socket_options.
    // encrypt_socket_options extends socket_options (interface address, multicast
    // TTL, etc.) with a nested encrypt_options field.
    // sender_id must be non-zero. Real deployments should derive it from a stable
    // device identity (e.g., a truncated hash of the MAC address or a UUID).
    mdnspp::encrypt_socket_options sock_opts{
        .encrypt = {
            .psk       = std::move(psk),
            .sender_id = 0x00000001,
            // accept_cleartext defaults to false: unencrypted packets are dropped.
            // Set to true during gradual migration if legacy (plain) peers are present.
        },
    };

    // Step 3: Construct the encrypted observer.
    // encrypted_observer is defined in mdnspp/encrypt/defaults.h as:
    //   using encrypted_observer = basic_observer<encrypted_policy<DefaultPolicy>>;
    // Constructor order: (executor, observer_options, encrypt_socket_options).
    mdnspp::context ctx;

    mdnspp::encrypted_observer obs{
        ctx,
        // Step 4: observer_options carries the per-record callback.
        // on_record receives fully decrypted mdns_record_variant values.
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender,
                            const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&sender](const auto &r) {
                    std::cout << sender << " -> " << r << std::endl;
                }, rec);
            }
        },
        std::move(sock_opts),
    };

    obs.async_observe([&ctx](std::error_code ec)
    {
        if (ec)
            std::cerr << "observe error: " << ec.message() << std::endl;
        ctx.stop();
    });

    ctx.run();
}
