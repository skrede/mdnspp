# encrypted defaults

Convenience type aliases for all public mdnspp types instantiated with `encrypted_policy<DefaultPolicy>`. These aliases mirror the standard `defaults.h` aliases (`observer`, `querier`, etc.) and are the recommended way to use encrypted mDNS without writing angle-bracket templates.

## Header

```cpp
#include <mdnspp/encrypt/defaults.h>
```

## Aliases

| Alias | Expansion | Base Template |
|-------|-----------|---------------|
| `encrypted_observer` | `basic_observer<encrypted_policy<DefaultPolicy>>` | `basic_observer` |
| `encrypted_querier` | `basic_querier<encrypted_policy<DefaultPolicy>>` | `basic_querier` |
| `encrypted_service_discovery` | `basic_service_discovery<encrypted_policy<DefaultPolicy>>` | `basic_service_discovery` |
| `encrypted_service_server` | `basic_service_server<encrypted_policy<DefaultPolicy>>` | `basic_service_server` |
| `encrypted_service_monitor` | `basic_service_monitor<encrypted_policy<DefaultPolicy>>` | `basic_service_monitor` |
| `encrypted_nic_monitor` | `basic_nic_monitor<encrypted_policy<DefaultPolicy>>` | `basic_nic_monitor` |
| `encrypted_nic_group_options` | `basic_nic_group_options<encrypted_policy<DefaultPolicy>>` | `basic_nic_group_options` |
| `encrypted_dynamic_nic_group` | `dynamic_nic_group<encrypted_policy<DefaultPolicy>>` | `dynamic_nic_group` |
| `encrypted_nic_group<Peers...>` | `basic_nic_group<encrypted_policy<DefaultPolicy>, Peers...>` | `basic_nic_group` |

The last entry is a template alias:

```cpp
template <template <typename...> class... Peers>
using encrypted_nic_group = basic_nic_group<encrypted_policy<DefaultPolicy>, Peers...>;
```

## Declarations

```cpp
namespace mdnspp {

using encrypted_observer          = basic_observer<encrypted_policy<DefaultPolicy>>;
using encrypted_querier           = basic_querier<encrypted_policy<DefaultPolicy>>;
using encrypted_service_discovery = basic_service_discovery<encrypted_policy<DefaultPolicy>>;
using encrypted_service_server    = basic_service_server<encrypted_policy<DefaultPolicy>>;
using encrypted_service_monitor   = basic_service_monitor<encrypted_policy<DefaultPolicy>>;
using encrypted_nic_monitor       = basic_nic_monitor<encrypted_policy<DefaultPolicy>>;
using encrypted_nic_group_options = basic_nic_group_options<encrypted_policy<DefaultPolicy>>;
using encrypted_dynamic_nic_group = dynamic_nic_group<encrypted_policy<DefaultPolicy>>;

template <template <typename...> class... Peers>
using encrypted_nic_group = basic_nic_group<encrypted_policy<DefaultPolicy>, Peers...>;

}
```

## What This Header Includes

`<mdnspp/encrypt/defaults.h>` includes transitively:
- All seven `basic_*.h` headers
- `<mdnspp/encrypt/encrypted_policy.h>` (and its dependencies)
- `<mdnspp/default/default_policy.h>`

A single `#include <mdnspp/encrypt/defaults.h>` is sufficient for all encrypted mDNS usage with `DefaultPolicy`.

## Constructor Signatures

Each alias inherits the full constructor set of its base template. Because `encrypted_policy<DefaultPolicy>` declares `socket_options_type = encrypt_socket_options`, the constructors accepting options take `encrypt_socket_options` (not the base `socket_options`).

All aliases offer the same two-constructor pattern as their base type:

```cpp
// Throwing
encrypted_observer(executor_type ex,
                   observer_options opts   = {},
                   encrypt_socket_options  = {},
                   mdns_options mdns_opts  = {});

// Non-throwing
encrypted_observer(executor_type ex,
                   observer_options opts,
                   encrypt_socket_options,
                   mdns_options mdns_opts,
                   std::error_code &ec);
```

The `executor_type` for all aliases is `mdnspp::context` (the `DefaultPolicy` executor).

## Usage Example

```cpp
#include <mdnspp/encrypt/defaults.h>
#include <mdnspp/encrypt/encrypt_socket_options.h>

#include <array>
#include <iostream>

int main()
{
    std::array<std::byte, 32> raw_key{};
    // ... populate raw_key ...

    mdnspp::encrypt_socket_options sock_opts;
    sock_opts.encrypt.psk       = mdnspp::secure_key{raw_key};
    sock_opts.encrypt.sender_id = 1;

    mdnspp::context ctx;

    mdnspp::encrypted_observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender,
                            const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&](const auto &r) {
                    std::cout << sender << " -> " << r << std::endl;
                }, rec);
            }
        },
        std::move(sock_opts)
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}
```

## See Also

- [encrypted_policy](encrypted_policy.md) -- the policy wrapper behind all these aliases
- [encrypt_socket_options](encrypt_socket_options.md) -- options accepted by the constructors
- [Encrypted mDNS Guide](../encrypted-mdns.md) -- setup, key rotation, auth-only mode
- [observer](../../api/observer.md) -- base observer API reference
