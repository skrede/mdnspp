#include "mdnspp/encrypt/defaults.h"

#include <array>
#include <cstddef>
#include <utility>
#include <iostream>
#include <variant>

// Demonstrate encrypted mDNS in auth-only mode.
//
// Auth-only mode provides packet authentication without confidentiality.
// The DNS payload is transmitted in plaintext, but a Poly1305 authentication
// tag covers the 44-byte packet header and the plaintext payload. Any peer
// without the PSK cannot forge an authenticated packet, and any modification
// to the header or payload in transit is detected and the packet dropped.
//
// Wire format difference:
//   In full encryption mode, the flags byte in the packet header has bit 0 set
//   (flag_encrypted = 0x01) and the payload field contains ciphertext.
//   In auth-only mode, bit 0 is cleared (flags = 0x00) and the payload field
//   carries the raw plaintext DNS message. The 60-byte overhead is identical.
//
// receive_mode controls which packet types are accepted on the receive path:
//   receive_mode::accept_both      -- accepts encrypted and auth-only packets
//   receive_mode::encrypted_only   -- accepts only encrypted packets (drops auth-only)
//   receive_mode::auth_only   -- accepts only auth-only packets (drops encrypted)
//
// Use cases:
//   - Debugging: plaintext payloads are visible in Wireshark and other capture
//     tools, making it possible to inspect mDNS traffic without the PSK.
//   - Gradual deployment: auth-only senders can be verified by receivers before
//     a fleet-wide switch to full encryption.
//   - Monitoring: diagnostic peers can inspect DNS records while still
//     benefiting from packet authentication guarantees.

int main()
{
    std::array<std::byte, 32> raw_key{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
        std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C},
        std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F}, std::byte{0x10},
        std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18},
        std::byte{0x19}, std::byte{0x1A}, std::byte{0x1B}, std::byte{0x1C},
        std::byte{0x1D}, std::byte{0x1E}, std::byte{0x1F}, std::byte{0x20},
    };

    // auth_only = true: this socket sends plaintext payloads with a Poly1305 tag.
    // recv_mode = auth_only: this socket drops fully encrypted packets;
    // only auth-only packets from peers are passed through to the application.
    // Remove recv_mode (or use accept_both) to also accept encrypted packets.
    mdnspp::encrypt::encrypt_socket_options sock_opts{
        .encrypt = {
            .psk       = mdnspp::encrypt::secure_key{raw_key},
            .sender_id = 0x00000002,
            .auth_only = true,
            .recv_mode = mdnspp::encrypt::receive_mode::auth_only,
        },
    };

    mdnspp::context ctx;

    mdnspp::encrypt::encrypted_observer obs{
        ctx,
        mdnspp::observer_options{
            // Received records are authenticated (Poly1305 verified) but the
            // payloads arrived in plaintext. The application still sees
            // mdns_record_variant values; auth-only mode is transparent above
            // the socket layer.
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
