[![Build](https://github.com/skrede/mdnspp/actions/workflows/config.yaml/badge.svg)](https://github.com/skrede/mdnspp/actions/workflows/config.yaml)

# mdnspp
Multicast DNS (mDNS) is a zero configuration service for resolving hostnames to IP addresses on (small) networks without a local name server. 

This library is a cross-platform C++20 wrapper for the C library [mjansson/mdns](https://github.com/mjansson/mdns).
The wrapped library implements mDNS according to [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) and [RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763),
including the networking, serialization and deserialization of packets.

Besides creating a C++ wrapper for the original library, simple logger/sink interfaces are provided to redirect or disable printouts.

## Features
* **Services** \
Resolve hostname to ipv4 and ipv6 addresses, and provides text resources. (PTR, A, AAAA, SRV and TXT).

* **Service discovery**\
Zero configuration service discovery using mDNS.

* **Query**\
Send queries to resolve hostnames (A and AAAA) or for resources provided by specific services. 

* **Observation**\
Continuous monitoring of mDNS traffic.

## Examples
Check `examples/` for a full description of how to use this wrapper library. To build them, pass `-DMDNSPP_BUILD_EXAMPLES=ON` to CMake.

### Service servers
Setting up a service requires a hostname (e.g. "audhumbla"), a service name (e.g. "_mdnspp-service._udp.local."), and any text (TXT) resources. TXT records can have a key and value, or just a key.
```cpp
mdnspp::service_server s("unique_service_name", "_mdnspp-service._udp.local.");
s.serve({
        {"flag", std::nullopt},
        {"key", "value"}
    }
);
```

### Service discovery
The following will print the discovered services to stdout,
```cpp
mdnspp::service_discovery d;
d.discover();
```
which can produce the following.
```txt
[info] Local IPv4 address: 192.168.1.169
[info] Local IPv6 address: fd9d:94d3:e296:a140:dba3:68ed:6136:7129
[info] 192.168.1.169:5353: ANSWER PTR _services._dns-sd._udp.local. rclass 0x1 ttl 10 length 18
[info] [fe80::38ec:d87a:32f:b30c%enp5s0]:5353: ANSWER PTR _services._dns-sd._udp.local. rclass 0x1 ttl 10 length 18
[info] 192.168.1.107:5353: ANSWER PTR _services._dns-sd._udp.local. rclass 0x1 ttl 10 length 19
[info] [fe80::a611:62ff:fe9c:166f%enp5s0]:5353: ANSWER PTR _services._dns-sd._udp.local. rclass 0x1 ttl 10 length 19
[info] 192.168.1.49:5353: ANSWER PTR _services._dns-sd._udp.local. rclass 0x1 ttl 4500 length 13
[info] 192.168.1.178:5353: ANSWER PTR _services._dns-sd._udp.local. rclass 0x1 ttl 4500 length 13
```
The discovery can be called with a list of whitelisting criteria, such that records that do not at least one criteria are discarded. 
```cpp
mdnspp::service_discovery d;
d.discover({
    [](const std::shared_ptr<mdnspp::record_t> &record)
    {
        return record->sender_address.starts_with("192.168.1.169");
    }
});
```

### Queries
Queries can be used to resolve specific hostnames ("audhumbla.local.") to ipv4 or ipv6 addresses without using discovery, or to retrieve service pointers. 
```cpp
mdnspp::querent d;
d.query({
        "unique_service_name.local.",
        MDNS_RECORDTYPE_ANY
});
```
The above produces the following output when the service example is running.
```txt
[info] Local IPv4 address: 192.168.1.169
[info] Local IPv6 address: fd9d:94d3:e296:a140:dba3:68ed:6136:7129
[info] 192.168.1.169:5353: ANSWER A unique_service_name.local. rclass 0x1 ttl 10 length 4
[info] 192.168.1.169:5353: ADDITIONAL AAAA unique_service_name.local. rclass 0x1 ttl 10 length 16
[info] 192.168.1.169:5353: ADDITIONAL TXT flag rclass 0x1 ttl 10 length 16
[info] 192.168.1.169:5353: ADDITIONAL TXT key=value rclass 0x1 ttl 10 length 16
[info] [fe80::38ec:d87a:32f:b30c%enp5s0]:5353: ANSWER A unique_service_name.local. rclass 0x1 ttl 10 length 4
[info] [fe80::38ec:d87a:32f:b30c%enp5s0]:5353: ADDITIONAL AAAA unique_service_name.local. rclass 0x1 ttl 10 length 16
[info] [fe80::38ec:d87a:32f:b30c%enp5s0]:5353: ADDITIONAL TXT flag rclass 0x1 ttl 10 length 16
[info] [fe80::38ec:d87a:32f:b30c%enp5s0]:5353: ADDITIONAL TXT key=value rclass 0x1 ttl 10 length 16
```

### Logging
Implement a custom log sink to handle log messages if prints to stdout is not desired. 
```cpp
class example_sink : public mdnspp::log_sink
{
public:
    ~example_sink() override = default;

    void log(mdnspp::log_level level, const std::string &string) noexcept override
    {
        // redirect the printouts e.g., to file, or wrap around another logger implementation.
    }
};

mdnspp::querent d(std::make_shared<example_sink>());
d.query({
        "unique_service_name.local.",
        MDNS_RECORDTYPE_ANY
});
```

### Sending log messages from custom types
If deriving a class from `mdns_base`, log messages can be sent with various log levels as shown below. 
These methods return a logger instance which builds the log message string using streams, and `log_sink::log()` is invoked when the logger instance is destroyed.
The loggers can be used as an anonymous temporary variable,
```cpp
trace() << "This is a trace message";
```
or stored to a variable such that a multipart message can be constructed and logged once the logger goes out of scope:
```
{
    auto debug_logger = debug();
    debug_logger << "This is the first part of the message. ";
    if(some_condition)
        debug_logger << "some_condition was true. ";
    else
        debug_logger << "some_condition was false. ";
    debug_logger << "This is the last part of the message. This scope exits now, and the logger is destroyed.";
}
```

## Limitations
The following limitations are related to _mdnspp_ and not the original C library.

The original C library provides an implementation according to the relevant RFC.
However, much is left out of the implementation to users of the library in terms creating or handling requests and responses:
requests must be responded to correctly, and records must be constructed correctly.

There could be bugs related to the construction of records and responses performed by this library, which has not been extensively tested against 3rd party implementations.
For example, there has been no systematic testing against Avahi or Apple's Bonjour beyond discovering known and expected Apple products on the local network.

The test coverage of this library is practically NIL.

* A and AAAA records are only made for the first adapter encountered in each family (ipv4 and ipv6). This might be fixed at some point. 
* Services automatically serve A and AAAA records on the first network interface in each family; it does not permit to specify individual interfaces to use (or not use).
* This wrapper library has not been tested extensively in a multithreaded environment.