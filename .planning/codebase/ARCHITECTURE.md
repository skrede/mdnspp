# Architecture

**Analysis Date:** 2026-03-03

## Pattern Overview

**Overall:** Template Method + Strategy Pattern with Platform Abstraction

**Key Characteristics:**
- Abstract base class (`mdns_base`) defines socket lifecycle and listening loops
- Concrete subclasses implement specific mDNS roles: service publishing, discovery, querying, and monitoring
- Record data flows through a buffer-parser-handler chain
- Callback mechanism bridges low-level C library with C++ type system
- Pluggable logging via sink interface

## Layers

**Abstraction Layer (C++ Wrapper):**
- Purpose: Encapsulate mDNS protocol details and socket management, expose high-level C++ interfaces
- Location: `include/mdnspp/`, `src/mdnspp/`
- Contains: Classes for service serving, discovery, queries, observation, and record types
- Depends on: `mdns.h` (mjansson/mdns C library), standard C++ library, platform-specific socket APIs
- Used by: Applications using mdnspp

**Socket Management Layer:**
- Purpose: Manage IPv4/IPv6 sockets, handle platform differences (Windows/Unix)
- Location: `src/mdnspp/mdns_base.cpp`, `src/mdnspp/mdns_util.cpp`
- Contains: Socket creation, listener loops with select(), socket cleanup
- Depends on: Platform APIs (Winsock2, POSIX sockets)
- Used by: `mdns_base` and all subclasses

**Protocol Handler Layer:**
- Purpose: Parse raw mDNS packets and dispatch to application callbacks
- Location: `src/mdnspp/record_parser.cpp`, `src/mdnspp/record_builder.cpp`
- Contains: Record type-specific parsing (PTR, SRV, A, AAAA, TXT), record construction for responses
- Depends on: `mdns.h` functions for packet parsing/encoding
- Used by: Service server, discovery, querent, observer

**Data Model Layer:**
- Purpose: Define C++ types for mDNS records and configuration
- Location: `include/mdnspp/records.h`, `include/mdnspp/record_buffer.h`
- Contains: Type-specific record structures (record_ptr_t, record_srv_t, record_a_t, record_aaaa_t, record_txt_t), base record_t, query_t, service_txt
- Depends on: mdns.h enums and types
- Used by: Parser, builder, all handlers

**Logging Layer:**
- Purpose: Decouple logging output from core logic
- Location: `include/mdnspp/logger.h`, `include/mdnspp/log.h`
- Contains: log_sink interface (virtual base), log_sink_s<> for streams, log_sink_f<> for function callbacks, logger<> template for building messages
- Depends on: None (pure abstraction)
- Used by: mdns_base and all subclasses

## Data Flow

**Service Discovery Flow:**

1. Application creates `service_discovery` instance (optionally with callback)
2. `discover()` opens IPv4/IPv6 client sockets
3. Sends DNS-SD discovery query via `mdns_discovery_send()`
4. Enters `listen_until_silence()` loop: polls sockets with select(), timeout expires when no data received
5. Low-level C callback `mdns_base::mdns_callback()` invoked for each record
6. Callback wraps buffer data in `record_buffer` struct
7. Calls virtual `callback()` which `service_discovery::callback()` implements
8. `record_parser` parses the buffer data based on record type
9. Parses into typed record (`record_ptr_t`, `record_srv_t`, etc.)
10. Applies filter chain (if any filters provided)
11. Invokes application callback (`m_on_discover()`) or logs record
12. Loop continues until timeout expires, sockets closed

**Service Serving Flow:**

1. Application creates `service_server` with instance name and service type
2. `serve()` or `serve_and_announce()` called with TXT records
3. `record_builder` initialized with service details, constructs record objects and mDNS-compatible structures
4. Service opens listening sockets on port 5353
5. Optional callback invoked when sockets open
6. Enters listening loop
7. For each incoming query, `service_server::callback()` dispatches to type-specific handler:
   - `serve_dns_sd()` for service discovery queries
   - `serve_ptr()` for PTR record queries
   - `serve_srv()` for SRV record queries
   - `serve_a()` for A record queries
   - `serve_aaaa()` for AAAA record queries
   - `serve_txt()` for TXT record queries
8. Each handler uses `record_builder` to construct appropriate response record
9. Response sent via low-level `mdns_*_send()` functions
10. `announce()` sends unsolicited announcements via builder
11. `stop()` sends goodbye records (TTL=0) before shutdown

**Querying Flow:**

1. Application creates `querent` instance
2. `query()` called with query_t or vector of queries, optional filters
3. Builds low-level `mdns_query_t` structures
4. Opens client sockets
5. Sends query via `mdns_query_send()`
6. Enters `listen_until_silence()` loop
7. Parses response records same as discovery flow
8. Applies filters and invokes callback or logs
9. Exits when silence timeout reached

**Observation Flow:**

1. Application creates `observer` instance (always listening, no queries sent)
2. `observe()` called with optional filters
3. Sets flag to enter continuous listen mode in background thread (inferred from atomic `m_running`)
4. Opens service sockets (port 5353, not ephemeral)
5. Continuous polling loop: parses all mDNS traffic, applies filters
6. Invokes callback for each matching record
7. Continues until `stop()` called

**State Management:**
- Socket count and descriptor array maintained in `mdns_base::m_sockets`
- Atomic `m_stop` flag controls listener loop exit (thread-safe)
- Service state tracked via `service_server::m_running` (atomic)
- Logging level stored as atomic for potential thread-safe updates
- Filters stored per-instance in vectors (applied during callback, not thread-safe during modification)
- Record builder maintains service definition state with mutex protection in service server

## Key Abstractions

**mdns_base (Template Method):**
- Purpose: Define socket lifecycle and listening loop skeleton
- Examples: `service_server`, `service_discovery`, `querent`, `observer`
- Pattern: Template Method - subclasses implement virtual `callback()` to handle parsed records

**record_buffer (Data Transfer Object):**
- Purpose: Encapsulate raw packet metadata without copying data
- Examples: Used in callbacks from C library
- Pattern: Immutable wrapper (const members except name_offset) around C structures, prevents copies

**record_parser (Strategy):**
- Purpose: Parse specific record types from buffer
- Examples: `parse()` dispatches to `record_parse_ptr()`, `record_parse_srv()`, etc.
- Pattern: Strategy pattern with type-specific parsing logic

**record_builder (Factory):**
- Purpose: Construct both C++ record types and low-level mdns_record_t structures for service announcements
- Examples: `record_ptr()` returns C++ struct, `mdns_record_ptr()` returns C-compatible struct
- Pattern: Dual representation builder - maintains parallel C++ and C data structures

**log_sink (Sink/Observer):**
- Purpose: Decouple logging backend from library code
- Examples: `log_sink_s<std::cout>` writes to stream, `log_sink_f<custom_func>` calls function, custom implementations inherit `log_sink`
- Pattern: Strategy/Observer - allows application to inject custom logging

**record_filter (Predicate):**
- Purpose: Provide configurable record filtering at discovery/query time
- Examples: Lambda functions checking sender address, record type, etc.
- Pattern: Function object / predicate - passed as `std::vector<std::function<bool(std::shared_ptr<record_t>)>>`

**logger<L> (Builder):**
- Purpose: Build log messages as streams, then flush when destroyed
- Examples: `debug() << "value=" << x;` constructs message via operator<< overload
- Pattern: Temporary object builder - leverages destructor for side effects

## Entry Points

**Service Server:**
- Location: `include/mdnspp/service_server.h`
- Triggers: Application instantiation with service name and instance
- Responsibilities: Accept incoming mDNS queries, respond with configured service records, announce service availability

**Service Discovery:**
- Location: `include/mdnspp/service_discovery.h`
- Triggers: Application calls `discover()` method
- Responsibilities: Send DNS-SD query, collect and filter matching records, invoke callback or log results

**Querent:**
- Location: `include/mdnspp/querent.h`
- Triggers: Application calls `query()` with query_t
- Responsibilities: Send mDNS query for specific hostnames or services, collect responses, filter and callback

**Observer:**
- Location: `include/mdnspp/observer.h`
- Triggers: Application calls `observe()` method
- Responsibilities: Continuously listen to mDNS traffic without sending queries, parse all records, apply filters, callback

## Error Handling

**Strategy:** Limited error handling in API layer (by design for wrapper). Relies on underlying C library behavior.

**Patterns:**
- Socket opening throws `std::runtime_error` if no sockets opened successfully
- Logging errors via error level messages rather than exceptions
- Malformed records return nullptr or fail silently in parser (no exceptions thrown)
- No error propagation from response sending - failures logged but don't interrupt listening

## Cross-Cutting Concerns

**Logging:** Every major operation logged via logger<> instances (trace, debug, info, warn, error levels). Sink injected at construction time. Hierarchical - each subclass inherits base logging methods.

**Validation:** Record parsing validates data against record type expectations. Builder validates service configuration at construction. No input sanitization (expects well-formed DNS data from C library).

**Threading:** Not thread-safe for shared state modification. Socket loops are blocking and synchronous. Atomic flags used for graceful shutdown (`m_stop`). Service running state is atomic for status checks. Listener loop not designed for concurrent callbacks. Mutex protects service_server record builder during updates.

**Platform Compatibility:** Conditional compilation for Windows (Winsock2) vs Unix (POSIX). Socket APIs abstracted to portable mdnspp utility functions. Timeout handling uses platform-specific timeval structures.

---

*Architecture analysis: 2026-03-03*
