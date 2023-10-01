# mdnspp
Multicast DNS (mDNS) is a zero configuration service for resolving hostnames to IP addresses on (small) networks without a local name server. 

This library is a cross-platform C++20 wrapper for the C library [mjansson/mdns](https://github.com/mjansson/mdns), which provides am implementation of the networking, serialization and deserialization of packets according to [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) and [RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763).
The use of [mjansson/mdns](https://github.com/mjansson/mdns) as implemented in _mdnspp_ is a C++ification of the examples in C provided with the original library, along with a simple logger/sink system so that printouts can be redirected or disabled entirely. 

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
mdnspp::service_server s("audhumbla", "_mdnspp-service._udp.local.");
s.serve({
            {"Odin", std::nullopt},
            {"Thor",  "Balder"}
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
[debug] Local IPv4 address: 192.168.1.169
[debug] Local IPv6 address: fd94:d3e2:96a1:40ee:fd2b:443d:311d:2542
[debug] Opened 2 client sockets
[info] 192.168.1.169:5353: ANSWER PTR _services._dns-sd._udp.local._mdnspp-service._udp.local. rclass 0x1 ttl 10 length 23
[info] [fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ANSWER PTR _services._dns-sd._udp.local._mdnspp-service._udp.local. rclass 0x1 ttl 10 length 23
[info] [fe80::10d5:beaf:7d72:6ebf%enp4s0]:5353: ANSWER PTR _services._dns-sd._udp.local._airplay._tcp.local. rclass 0x1 ttl 10 length 11
[info] 192.168.1.73:5353: ANSWER PTR _services._dns-sd._udp.local._airplay._tcp.local. rclass 0x1 ttl 10 length 11
[debug] Closed 2 sockets
```
Instead of printing any received record to stdout, a callback can be provided and each record type can be handled individually (or discarded if not relevant).
```cpp
mdnspp::service_discovery d(
    [](std::unique_ptr<mdnspp::record_t> record)
    {
        if(record->rtype == MDNS_RECORDTYPE_SRV)
            std::cout << mdnspp::record_as<mdnspp::record_srv_t>(*record);
    }
);
d.discover();
```

### Queries
Queries can be used to resolve specific hostnames ("audhumbla.local.") to ipv4 or ipv6 addresses without using discovery, or to retrieve service pointers. 
```cpp
mdnspp::querier d;
d.inquire(
{
    "audhumbla.local.",
    MDNS_RECORDTYPE_A
});
```
The above produces the following output when the service example is running.
```txt
[debug] Local IPv4 address: 192.168.1.169
[debug] Local IPv6 address: fd94:d3e2:96a1:40ee:fd2b:443d:311d:2542
[debug] Opened 2 client sockets
[debug] Query audhumbla.local. for A records
[debug] Listening for mDNS query responses
[info] 192.168.1.169:5353: ANSWER A audhumbla.local.192.168.1.169 rclass 0x1 ttl 10 length 4
[info] 192.168.1.169:5353: ADDITIONAL AAAA audhumbla.local.fd94:d3e2:96a1:40ee:fd2b:443d:311d:2542 rclass 0x1 ttl 10 length 16
[info] 192.168.1.169:5353: ADDITIONAL TXT Odin rclass 0x1 ttl 10 length 18
[info] 192.168.1.169:5353: ADDITIONAL TXT Thor=Balder rclass 0x1 ttl 10 length 18
[info] [fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ANSWER A audhumbla.local.192.168.1.169 rclass 0x1 ttl 10 length 4
[info] [fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ADDITIONAL AAAA audhumbla.local.fd94:d3e2:96a1:40ee:fd2b:443d:311d:2542 rclass 0x1 ttl 10 length 16
[info] [fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ADDITIONAL TXT Odin rclass 0x1 ttl 10 length 18
[info] [fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ADDITIONAL TXT Thor=Balder rclass 0x1 ttl 10 length 18
[debug] Closed 2 sockets
```

### Logging
Implement a custom log sink to handle log messages if prints to stdout is not desired. 
```cpp
class example_sink : public mdnspp::log_sink
{
public:
    ~example_sink() override = default;

    void log(log_level level, const std::string &string) noexcept override
    {
        // print to stdout and omit the log level.
        std::cout << string << std::endl;
    }
};

mdnspp::querier d(std::make_shared<example_sink>());
d.inquire(
{
    "audhumbla._mdnspp-service._udp.local.",
    MDNS_RECORDTYPE_TXT
});
```

```txt
Local IPv4 address: 192.168.1.169
Local IPv6 address: fd94:d3e2:96a1:40ee:fd2b:443d:311d:2542
Opened 2 client sockets
Query audhumbla._mdnspp-service._udp.local. for TXT records
Listening for mDNS query responses
192.168.1.169:5353: ANSWER TXT Odin rclass 0x1 ttl 10 length 18
192.168.1.169:5353: ANSWER TXT Thor=Balder rclass 0x1 ttl 10 length 18
[fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ANSWER TXT Odin rclass 0x1 ttl 10 length 18
[fe80::6bc8:6f04:b59c:b2ad%enp4s0]:5353: ANSWER TXT Thor=Balder rclass 0x1 ttl 10 length 18
Closed 2 sockets
```

### Sending log messages from custom types
If deriving a class from `mdns_base`, log messages can be sent with various log levels as shown below. These methods return a logger instance which builds the log message string using streams, and `log_sink::log()` is invoked when the logger instance is destroyed.
```cpp
trace() << "This is a trace message";
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
These limitations are related to _mdnspp_ and not the original C library.
While the original C library provides an implementation according to the RFC's, users of the library must utilize it correctly.
Specifically, mDNS requests must be handled and responded to correctly, and records must be constructed correctly.

There could be bugs related to the construction of records and responses performed by this library, which has not been extensively tested against 3rd party implementations.
For example, there has been no systematic testing against Avahi or Apple's Bonjour, however, 3rd party services are discovered on the network (such as Apple devices).

The test coverage of this library is currently NIL.

Lastly, related to `service_server`
* A and AAAA records are only made for the first adapter encountered in each family (ipv4 and ipv6). This will be fixed. 
* Services automatically serve A and AAAA records on the first network interface in each family, and does not facilitate to specify individual interfaces to use (or not use).