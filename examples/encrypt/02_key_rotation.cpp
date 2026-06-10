#include "mdnspp/encrypt/defaults.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <thread>
#include <utility>
#include <iostream>

// Demonstrate encrypted mDNS key rotation.
//
// Key rotation replaces the active PSK on a live encrypted_socket without
// dropping packets from peers that have not yet completed the rotation.
//
// Epoch semantics:
//   Each encrypted_socket tracks a 32-bit epoch counter, starting at 0.
//   update_key() atomically increments the epoch and stores the new key.
//   Every outgoing packet carries the current epoch in the wire header.
//
// Dual-key overlap:
//   Immediately after update_key(), the socket holds two keys:
//     - current key (epoch N):   used to encrypt outgoing packets and to
//       decrypt incoming packets with epoch = N.
//     - previous key (epoch N-1): used to decrypt incoming packets with
//       epoch = N-1, until the grace period expires.
//   Packets with epoch < N-1 are always rejected immediately.
//
// Grace period:
//   grace_period carries the overlap window. At least one of duration or
//   packet_count must be set. When both are set, the grace period ends when
//   either condition is first satisfied.
//     .duration     -- expire after this wall-clock duration
//     .packet_count -- expire after this many old-epoch packets are received
//
// Lazy expiry:
//   The grace period is checked inline on each received old-epoch packet.
//   There is no background timer.
//
// Peer coordination:
//   All peers must call update_key() with the same new key. A practical
//   strategy: broadcast a rotation signal (e.g., a service TXT attribute),
//   then all peers load the new key and call update_key() within the grace
//   window. The grace period must be long enough to ensure that no peer is
//   still using the old key after it expires on the receiver side.
//
// After grace expires:
//   Packets from the previous epoch are rejected. Any peer that has not
//   rotated will be unable to communicate until it also calls update_key()
//   with the new key.

int main()
{
    std::array<std::byte, 32> initial_key{
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
        std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}, std::byte{0x0C},
        std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F}, std::byte{0x10},
        std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18},
        std::byte{0x19}, std::byte{0x1A}, std::byte{0x1B}, std::byte{0x1C},
        std::byte{0x1D}, std::byte{0x1E}, std::byte{0x1F}, std::byte{0x20},
    };

    mdnspp::encrypt::encrypt_socket_options sock_opts{
        .encrypt = {
            .psk       = mdnspp::encrypt::secure_key{initial_key},
            .sender_id = 0x00000001,
        },
    };

    mdnspp::context ctx;

    mdnspp::encrypt::encrypted_observer obs{
        ctx,
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

    // Simulate a key rotation after 5 seconds.
    // In a real application, the rotation would be triggered by an application-
    // level signal (e.g., a scheduled rotation, an admin command, or a shared
    // rotation notification received over a side-channel).
    std::thread rotation_thread{[&obs, &ctx]
    {
        std::this_thread::sleep_for(std::chrono::seconds{5});

        std::array<std::byte, 32> new_raw_key{
            std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}, std::byte{0xA4},
            std::byte{0xA5}, std::byte{0xA6}, std::byte{0xA7}, std::byte{0xA8},
            std::byte{0xA9}, std::byte{0xAA}, std::byte{0xAB}, std::byte{0xAC},
            std::byte{0xAD}, std::byte{0xAE}, std::byte{0xAF}, std::byte{0xB0},
            std::byte{0xB1}, std::byte{0xB2}, std::byte{0xB3}, std::byte{0xB4},
            std::byte{0xB5}, std::byte{0xB6}, std::byte{0xB7}, std::byte{0xB8},
            std::byte{0xB9}, std::byte{0xBA}, std::byte{0xBB}, std::byte{0xBC},
            std::byte{0xBD}, std::byte{0xBE}, std::byte{0xBF}, std::byte{0xC0},
        };

        // update_key() is called on the encrypted_socket, accessible via socket().
        // socket() returns the encrypted_socket<InnerSocket> for encrypted_policy.
        // The grace period of 30 seconds allows peers that have not yet rotated to
        // continue decrypting with the old key during the transition window.
        obs.socket().update_key(
            mdnspp::encrypt::secure_key{new_raw_key},
            mdnspp::encrypt::grace_period{
                .duration     = std::chrono::seconds{30},
                .packet_count = 1000,
            }
        );

        std::cout << "key rotated -- epoch incremented, grace period: 30 s or 1000 packets\n";

        // After 35 seconds the grace period has expired on this peer. Any packets
        // still arriving with the old epoch are rejected from this point on.
        std::this_thread::sleep_for(std::chrono::seconds{35});
        ctx.stop();
    }};

    ctx.run();
    rotation_thread.join();
}
