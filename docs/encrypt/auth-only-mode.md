# Auth-Only Mode

Auth-only mode provides packet authentication without confidentiality. The DNS
payload is transmitted in plaintext but is covered by a Poly1305 authentication
tag, allowing the receiver to verify that the packet was produced by a peer that
holds the PSK and has not been tampered with.

## Wire Format Difference

In full encryption mode the `flags` byte in `encrypted_packet_header` has bit 0
set (`flag_encrypted = 0x01`). In auth-only mode that bit is cleared (`flags =
0x00`), and the payload field carries the raw plaintext DNS message instead of
ciphertext.

The Poly1305 authentication tag still covers the 44-byte header and the payload
bytes as AAD (Additional Authenticated Data), so any modification to either
region is detected. The 60-byte overhead (44-byte header + 16-byte tag) is
identical to full encryption mode.

## Sender Configuration

Set `encrypt_options::auth_only = true` to make the sender produce auth-only
packets:

```cpp
mdnspp::encrypt::encrypt_socket_options opts{
    .encrypt = {
        .psk       = mdnspp::encrypt::secure_key{raw_key},
        .sender_id = 0x00000002,
        .auth_only = true,
    },
};
```

All outgoing packets from this socket carry the plaintext payload with a
Poly1305 tag. Incoming packets are still decrypted or authenticated according to
`recv_mode` (see below).

## receive_mode

The `receive_mode` enum controls which incoming packet types the receiver
accepts:

| Value | Accepted packets |
|---|---|
| `receive_mode::accept_both` | Both encrypted (`flags = 0x01`) and auth-only (`flags = 0x00`) packets |
| `receive_mode::encrypted_only` | Only encrypted packets; auth-only packets are silently dropped |
| `receive_mode::auth_only` | Only auth-only packets; encrypted packets are silently dropped |

`receive_mode` is independent of `auth_only`. A receiver can accept auth-only
packets from a sender that is in auth-only mode while itself sending fully
encrypted packets, or vice versa.

Setting `recv_mode = receive_mode::auth_only` together with `auth_only =
false` creates a receiver that only accepts auth-only packets but sends
encrypted ones.

## Use Cases

**Debugging and packet capture**: auth-only traffic can be inspected with
standard packet capture tools (e.g., Wireshark) because the DNS payload is
not obfuscated. The authentication tag still prevents injection of forged
packets by observers without the PSK.

**Gradual deployment**: in a network where some peers have been updated to use
encrypted mDNS and others have not, setting `accept_cleartext = true` alongside
`auth_only = true` allows upgraded peers to authenticate each other while still
receiving cleartext from legacy peers.

**Warning — unauthenticated downgrade path.** `accept_cleartext = true`
forwards packets classified as cleartext with *no* authentication whatsoever:
any sender on the LAN bypasses every guarantee of this extension (origin
authentication, integrity, anti-replay) by sending a packet without the 0x4D43
magic prefix. During a gradual deployment the effective security level is
therefore that of plain mDNS, regardless of how many peers already
authenticate. Treat the combination as a migration tool with a planned end
date, and set `accept_cleartext = false` (or `cleartext_detection::reject_all`)
once all peers are upgraded. See the
[Threat Model](threat-model.md#cleartext-downgrade-via-accept_cleartext--not-protected).

**Monitoring and diagnostics**: a monitoring peer that needs to inspect DNS
records for debugging can operate in auth-only mode to preserve visibility
without removing the authentication guarantee.

## Code Example

```cpp
#include "mdnspp/encrypt/defaults.h"

#include <iostream>

int main()
{
    std::array<std::byte, 32> raw_key{};
    // ... load raw_key ...

    mdnspp::encrypt::encrypt_socket_options opts{
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
            .on_record = [](const mdnspp::endpoint &,
                            const mdnspp::mdns_record_variant &rec)
            {
                std::visit([](const auto &r) { std::cout << r << std::endl; }, rec);
            }
        },
        std::move(opts)
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}
```

This observer sends auth-only packets and accepts only auth-only packets from
peers. A Wireshark capture of the multicast traffic shows plaintext DNS
payloads, while peers without the PSK cannot forge authenticated packets.
