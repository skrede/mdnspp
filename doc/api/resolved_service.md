# resolved_service

Aggregated view of a discovered mDNS service instance. Combines PTR, SRV, A, AAAA, and TXT records into a single value type following RFC 6763 name-chain correlation.

## Header

```cpp
#include <mdnspp/resolved_service.h>
```

## Fields

```cpp
struct resolved_service {
    std::string              instance_name;    // fully-qualified instance name (from PTR)
    std::string              hostname;         // target hostname (from SRV)
    uint16_t                 port{0};          // service port (from SRV)
    std::vector<service_txt> txt_entries;      // key/value pairs (from TXT)
    std::vector<std::string> ipv4_addresses;   // IPv4 addresses (from A records)
    std::vector<std::string> ipv6_addresses;   // IPv6 addresses (from AAAA records)
};
```

| Field | Type | Source Record | Description |
|-------|------|---------------|-------------|
| `instance_name` | `std::string` | PTR | Fully-qualified service instance name (e.g. `"MyApp._http._tcp.local"`) |
| `hostname` | `std::string` | SRV | Target hostname (e.g. `"myhost.local"`) |
| `port` | `uint16_t` | SRV | TCP/UDP port the service listens on |
| `txt_entries` | `std::vector<service_txt>` | TXT | Key/value metadata pairs |
| `ipv4_addresses` | `std::vector<std::string>` | A | IPv4 address strings (e.g. `"192.168.1.10"`) |
| `ipv6_addresses` | `std::vector<std::string>` | AAAA | IPv6 address strings (e.g. `"fe80::1"`) |

### service_txt

```cpp
struct service_txt {
    std::string                key;
    std::optional<std::string> value;
};
```

Defined in `<mdnspp/records.h>`. Represents a single RFC 6763 TXT key/value pair. Key-only entries have `value == std::nullopt`.

## aggregate()

```cpp
std::vector<resolved_service> aggregate(std::span<const mdns_record_variant> records);
std::vector<resolved_service> aggregate(const std::vector<mdns_record_variant>& records);
```

Free function that correlates a flat sequence of mDNS records into `resolved_service` values using RFC 6763 name-chain correlation:

1. **PTR** records seed new service entries (each `ptr_name` becomes an `instance_name`)
2. **SRV** records provide `hostname` and `port` (matched by `name == instance_name`)
3. **TXT** records provide `txt_entries` (matched by `name == instance_name`)
4. **A/AAAA** records provide addresses (matched by `name == SRV hostname`)

A two-pass algorithm ensures A/AAAA records arriving before their SRV record are still correlated correctly.

**Deduplication rules:**
- IP addresses: deduplicated by value
- TXT entries: deduplicated by key (latest value wins)
- SRV hostname/port: latest SRV record wins

Partial services (missing SRV, TXT, or address records) are included with empty fields -- they are never dropped.

## Usage Example

```cpp
// Discover HTTP services and print resolved service details.

#include <mdnspp/defaults.h>
#include <mdnspp/resolved_service.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx};

    sd.async_browse("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::resolved_service> services)
        {
            if (ec)
            {
                std::cerr << "browse error: " << ec.message() << "\n";
            }
            else
            {
                std::cout << "Found " << services.size() << " service(s):\n";
                for (const auto& svc : services)
                {
                    std::cout << "  " << svc.instance_name << "\n"
                              << "    host: " << svc.hostname
                              << " port: " << svc.port << "\n";

                    for (const auto& addr : svc.ipv4_addresses)
                        std::cout << "    IPv4: " << addr << "\n";

                    for (const auto& addr : svc.ipv6_addresses)
                        std::cout << "    IPv6: " << addr << "\n";

                    for (const auto& txt : svc.txt_entries)
                    {
                        std::cout << "    TXT: " << txt.key;
                        if (txt.value)
                            std::cout << "=" << *txt.value;
                        std::cout << "\n";
                    }
                }
            }

            ctx.stop();  // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

## See Also

- [service_discovery](service_discovery.md) -- discover and browse services
- [querier](querier.md) -- lower-level record queries
