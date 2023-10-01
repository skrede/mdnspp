#ifndef MDNSPP_MDNS_UTIL_H
#define MDNSPP_MDNS_UTIL_H

/*
 * Adapted from https://github.com/mjansson/mdns/blob/main/mdns.c
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <string>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#define sleep(x) Sleep(x * 1000)
#else
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/time.h>
#endif

#include <mdns.h>

namespace mdnspp {

int open_client_sockets(int *sockets, int max_sockets, int port, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6);
int open_service_sockets(int *sockets, int max_sockets, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6); // Open sockets to listen to incoming mDNS queries on port 5353

std::string ip_address_to_string(const sockaddr *addr, size_t addrlen);
std::string ip_address_to_string(const sockaddr_in &addr);
std::string ip_address_to_string(const sockaddr_in6 &addr);

mdns_string_t ipv4_address_to_string(char *buffer, size_t capacity, const struct sockaddr_in *addr, size_t addrlen);
mdns_string_t ipv6_address_to_string(char *buffer, size_t capacity, const struct sockaddr_in6 *addr, size_t addrlen);

}

#endif
