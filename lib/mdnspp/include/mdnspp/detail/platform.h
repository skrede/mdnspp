#ifndef HPP_GUARD_MDNSPP_PLATFORM_H
#define HPP_GUARD_MDNSPP_PLATFORM_H

// platform.h — cross-platform socket includes.
// Provides the minimal set of headers required for BSD-socket and poll APIs.
// Windows supplements with a nfds_t typedef (not provided by winsock headers).

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
// nfds_t is not provided by Windows headers
using nfds_t = unsigned long;
#else
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <poll.h>
#endif

#endif // HPP_GUARD_MDNSPP_PLATFORM_H
