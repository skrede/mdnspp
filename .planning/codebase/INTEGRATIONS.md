# External Integrations

**Analysis Date:** 2026-03-03

## APIs & External Services

**mDNS Protocol:**
- RFC 6762 (Multicast DNS) - Service name resolution protocol
  - Standard port: UDP 5353
  - Multicast addresses: 224.0.0.251 (IPv4), ff02::fb (IPv6)
  - Implementation: Wrapped from mjansson/mdns C library

**DNS-SD (Service Discovery):**
- RFC 6763 - DNS-based service discovery
  - PTR records for service enumeration
  - SRV records for service location
  - A/AAAA records for address resolution
  - TXT records for service metadata

## Network Integration

**Socket Management:**
- Direct socket APIs via mdns C library
  - IPv4 unicast and multicast (224.0.0.251:5353)
  - IPv6 unicast and multicast (ff02::fb:5353)
  - Platform-specific: WinSock on Windows, POSIX sockets on Unix/Linux/macOS

**Service Roles:**
- **Querent** (`querent.h`/`querent.cpp`) - Sends mDNS queries, receives responses
  - Listen timeout configurable
  - Used for hostname resolution and resource queries

- **Observer** (`observer.h`/`observer.cpp`) - Passive mDNS traffic monitoring
  - Continuous listening to multicast traffic
  - No responses generated

- **Service Server** (`service_server.h`/`service_server.cpp`) - Advertises services
  - Responds to queries for registered services
  - Handles PTR, SRV, A, AAAA, TXT record queries
  - Multicast socket and unicast response capability
  - Configurable buffer sizes and timeouts

- **Service Discovery** (`service_discovery.h`/`service_discovery.cpp`) - Active service enumeration
  - Queries for all available services (_services._dns-sd._udp.local.)
  - Filters results via callback functions
  - IPv4 and IPv6 capable

## Data Records

**Supported Record Types:**
- **PTR** (Pointer) - Service instance enumeration
  - Implemented: `record_ptr_t` in `records.h`
  - Contains: pointer name reference

- **A** (Address) - IPv4 resolution
  - Implemented: `record_a_t` in `records.h`
  - Contains: sockaddr_in structure and string representation

- **AAAA** (Address) - IPv6 resolution
  - Implemented: `record_aaaa_t` in `records.h`
  - Contains: sockaddr_in6 structure and string representation

- **SRV** (Service) - Service location
  - Implemented: `record_srv_t` in `records.h`
  - Contains: port, weight, priority, service name

- **TXT** (Text) - Service metadata
  - Implemented: `record_txt_t` in `records.h`
  - Contains: key-value pairs (value optional)

**Record Processing:**
- Parser: `record_parser.cpp` - Extracts records from binary mDNS packets
- Builder: `record_builder.cpp` - Constructs mDNS responses from records
- Buffer: `record_buffer.h`/`record_buffer.cpp` - Manages packet buffers

## Logging & Observability

**Logging Framework:**
- Custom log sink interface: `log_sink` base class in `logger.h`
- Built-in implementations:
  - `log_sink_s<std::ostream&>` - Stream-based (defaults to std::cout)
  - `log_sink_f<function>` - Function callback-based

**Log Levels:**
```
trace  = 0x0001 - Detailed debugging information
debug  = 0x0002 - General debugging
info   = 0x0004 - Informational messages (default)
warn   = 0x0008 - Warning messages
err    = 0x0010 - Error messages
off    = 0x0020 - Disable logging
```

**Logger Methods:**
- `trace()`, `debug()`, `info()`, `warn()`, `error()` - Return logger objects
- Supports optional label parameter: `debug("label")`
- Stream-based message building with RAII destruction-time flushing
- Location: Methods defined in `mdns_base.h`, implementation in `mdns_base.cpp`

## Webhooks & Callbacks

**Query Callbacks:**
- Record filter callbacks: `record_filter` function type in `records.h`
  - Type: `std::function<bool(const std::shared_ptr<mdnspp::record_t>&)>`
  - Used to filter discovered records during discovery
  - Example: filter by sender address or record type

**Service Server Callbacks:**
- Socket open callback: `socket_open_callback` in `service_server.h`
  - Invoked after sockets open successfully
  - Allows initialization logic before service becomes responsive

**Record Callbacks:**
- Internal: `mdns_record_callback_fn` from mdns C library
  - Called by mdns library for each record in packets
  - Wrapped and translated to C++ record types

## Event Flow

**Service Discovery Flow:**
1. Open multicast sockets (IPv4 224.0.0.251:5353, IPv6 ff02::fb:5353)
2. Query for `_services._dns-sd._udp.local.` PTR records
3. Listen for responses (default 2 second timeout)
4. Parse records and apply filter callbacks
5. Close sockets

**Service Server Flow:**
1. Initialize with instance name and service name
2. Open service sockets (listening on 5353)
3. Call socket_open_callback if provided
4. Listen for incoming queries
5. Match queries against record types
6. Construct and send responses
7. Continue until stop() is called

**Querying Flow:**
1. Open client sockets on ephemeral port
2. Multicast query for specific record type
3. Listen for responses until timeout or silence
4. Parse and return all received records
5. Close sockets

## Environment Configuration

**No environment variables required** - Configuration is entirely programmatic via C++ API.

**Configurable Parameters:**
- `service_server::params` structure:
  - `recv_buf_size` - Receive buffer capacity (default: 2048 bytes)
  - `send_buf_size` - Send buffer capacity (default: 4096 bytes)
  - `timeout` - Listening timeout (default: 500ms)

- Logging:
  - Custom log sink instance
  - Log level (trace through off)

- Service discovery:
  - Record filter callbacks for selective discovery

---

*Integration audit: 2026-03-03*
